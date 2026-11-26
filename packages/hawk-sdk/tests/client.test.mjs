import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  HawkActionBlockedError,
  HawkApiError,
  HawkClient,
  assertHawkAllowed,
  assertToolSafe,
  hawkThreatFindings,
  hawkThreatTypes,
  normalizeHawkDecision,
} from "../dist/index.js";
import {
  HawkClient as HawkEndpointClient,
  HawkEndpointAuthorizationRequiredError,
  HawkEndpointTransport,
  assertEndpointAuthorized,
  verifyEndpointBrokerResponse,
} from "../dist/node-client.js";

const ENDPOINT_BROKER_KEY_PAIR = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const ENDPOINT_BROKER_PUBLIC_PEM = ENDPOINT_BROKER_KEY_PAIR.publicKey.export({
  type: "spki",
  format: "pem",
}).toString();
const ENDPOINT_BROKER_JWK = ENDPOINT_BROKER_KEY_PAIR.publicKey.export({ format: "jwk" });
const ENDPOINT_BROKER_THUMBPRINT = createHash("sha256").update(JSON.stringify({
  crv: "P-256",
  kty: "EC",
  x: ENDPOINT_BROKER_JWK.x,
  y: ENDPOINT_BROKER_JWK.y,
})).digest("hex");

function signedEndpointBrokerResponse(payload, issuedAt = Math.floor(Date.now() / 1000)) {
  const signedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const statement = [
    "hawk-local-broker-v1",
    "ES256",
    "endpoint-test",
    String(issuedAt),
    ENDPOINT_BROKER_THUMBPRINT,
    signedPayload,
  ].join("\n");
  return {
    ...payload,
    broker_auth: {
      version: "hawk-local-broker-v1",
      algorithm: "ES256",
      endpoint_id: "endpoint-test",
      issued_at: issuedAt,
      key_thumbprint: ENDPOINT_BROKER_THUMBPRINT,
      public_key_pem: ENDPOINT_BROKER_PUBLIC_PEM,
      signed_payload: signedPayload,
      signature: sign(
        "sha256",
        Buffer.from(statement),
        ENDPOINT_BROKER_KEY_PAIR.privateKey,
      ).toString("base64url"),
    },
  };
}

function endpointModeOptions(endpointSocketPath, options = {}) {
  return {
    mode: "endpoint",
    endpointSocketPath,
    endpointTrustedDeviceThumbprint: ENDPOINT_BROKER_THUMBPRINT,
    ...options,
  };
}

test("Node endpoint SDK trusts only the device-key-signed broker payload", () => {
  const response = signedEndpointBrokerResponse({
    ok: true,
    request_id: "request-1",
    action: "block",
    control_mode: "inline_prevented",
  });
  response.action = "allow";

  const verified = verifyEndpointBrokerResponse(response, ENDPOINT_BROKER_THUMBPRINT);

  assert.equal(verified.action, "block");
  assert.throws(
    () => verifyEndpointBrokerResponse(response, "0".repeat(64)),
    /Hawk endpoint authorization failed/,
  );
});

function jsonResponse(body, init = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: { "Content-Type": "application/json" },
  });
}

test("llmIntercept posts to the Hawk LLM gateway with tenant and bearer auth", async () => {
  const calls = [];
  const client = new HawkClient({
    apiUrl: "http://hawk.local:8000/",
    tenantId: "tenant-1",
    accessToken: "token-1",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({ final_decision: "allow", control_mode: "inline_allowed" });
    },
  });

  const result = await client.llmIntercept({
    ai_system_id: "chatgpt",
    actor_type: "human",
    actor_id: "user-1",
    prompt: "Summarize public company filings",
    provider: "openai",
    model: "gpt-4o",
  });

  assert.deepEqual(result, { final_decision: "allow", control_mode: "inline_allowed" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://hawk.local:8000/gateway/llm/intercept");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.Authorization, "Bearer token-1");
  assert.equal(calls[0].init.headers["X-Tenant-ID"], "tenant-1");
  assert.equal(calls[0].init.headers["X-Hawk-SDK"], "@hawk-ai/sdk/0.2.0");
  assert.equal(JSON.parse(calls[0].init.body).ai_system_id, "chatgpt");
});

test("mcpAuthorize posts tool action requests to the MCP authorization path", async () => {
  const calls = [];
  const client = new HawkClient({
    apiUrl: "http://hawk.local:8000",
    tenantId: "tenant-1",
    accessToken: "token-1",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({
        final_decision: "block",
        control_mode: "inline_prevented",
        reason_code: "high_risk_tool",
      });
    },
  });

  const result = await client.mcpAuthorize({
    ai_system_id: "developer-agent",
    actor_id: "agent-1",
    capability_token: "capability-token",
    action: "write_file",
    resource: "repo://payments/auth.py",
    tool_name: "write_file",
    chain_id: "chain-1",
  });

  assert.equal(result.final_decision, "block");
  assert.equal(calls[0].url, "http://hawk.local:8000/gateway/mcp/authorize");
  assert.equal(JSON.parse(calls[0].init.body).tool_name, "write_file");
});

test("scanMcpTool posts metadata for fingerprinting and drift detection", async () => {
  const calls = [];
  const client = new HawkClient({
    apiUrl: "http://hawk.local:8000",
    tenantId: "tenant-1",
    accessToken: "token-1",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({ trust_status: "unknown", finding_type: "UNAPPROVED_MCP_TOOL_VERSION" });
    },
  });

  const result = await client.scanMcpTool({
    mcp_server_id: "server-1",
    tool_name: "grant_role",
    tool_version: "1.0.0",
    description: "Grant a role",
    schema: { type: "object" },
  });

  assert.equal(result.trust_status, "unknown");
  assert.equal(calls[0].url, "http://hawk.local:8000/gateway/mcp/tools/scan");
  assert.equal(JSON.parse(calls[0].init.body).mcp_server_id, "server-1");
});

test("dataTransferCheck posts browser-visible data movement to runtime control", async () => {
  const calls = [];
  const client = new HawkClient({
    apiUrl: "http://hawk.local:8000",
    tenantId: "tenant-1",
    accessToken: "token-1",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return jsonResponse({
        decision: "require_justification",
        reason_code: "business_data_to_public_ai",
        justification_required: true,
      });
    },
  });

  const result = await client.dataTransferCheck({
    copy_context: {
      copied_text_hash: "hash-1",
      copied_text_preview_redacted: "Customer email: [email]",
    },
    paste_context: {
      destination_domain: "chatgpt.com",
      destination_surface_type: "public_ai",
    },
    extension_version: "0.1.3",
  });

  assert.equal(result.decision, "require_justification");
  assert.equal(calls[0].url, "http://hawk.local:8000/runtime-control/data-transfer-check");
});

test("throws HawkApiError with status and response body for failed API requests", async () => {
  const client = new HawkClient({
    apiUrl: "http://hawk.local:8000",
    tenantId: "tenant-1",
    accessToken: "token-1",
    fetchImpl: async () => jsonResponse({ detail: "not authenticated" }, { status: 401 }),
  });

  await assert.rejects(
    () =>
      client.llmIntercept({
        ai_system_id: "chatgpt",
        actor_type: "human",
        actor_id: "user-1",
        prompt: "hello",
      }),
    (error) => {
      assert.ok(error instanceof HawkApiError);
      assert.equal(error.status, 401);
      assert.deepEqual(error.body, { detail: "not authenticated" });
      return true;
    },
  );
});

test("normalizeHawkDecision treats warnings as allowed but visible", () => {
  const decision = normalizeHawkDecision({
    final_decision: "warn",
    control_mode: "warned",
    reason_code: "business_context_review",
  });

  assert.equal(decision.decision, "warn");
  assert.equal(decision.controlMode, "warned");
  assert.equal(decision.allowed, true);
  assert.equal(decision.blocked, false);
  assert.equal(decision.requiresReview, false);
  assert.equal(decision.reasonCode, "business_context_review");
});

test("assertHawkAllowed throws HawkActionBlockedError for inline-prevented decisions", () => {
  const response = {
    final_decision: "block",
    control_mode: "inline_prevented",
    reason_code: "secret_to_public_ai",
    evidence_bundle_id: "evidence-1",
  };

  assert.throws(
    () => assertHawkAllowed(response, "LLM call blocked by Hawk"),
    (error) => {
      assert.ok(error instanceof HawkActionBlockedError);
      assert.equal(error.message, "LLM call blocked by Hawk");
      assert.equal(error.decision, "block");
      assert.equal(error.controlMode, "inline_prevented");
      assert.equal(error.reasonCode, "secret_to_public_ai");
      assert.deepEqual(error.response, response);
      return true;
    },
  );
});

test("withLlmAuthorization does not execute the model callback when Hawk blocks", async () => {
  let executed = false;
  const client = new HawkClient({
    apiUrl: "http://hawk.local:8000",
    tenantId: "tenant-1",
    accessToken: "token-1",
    fetchImpl: async () =>
      jsonResponse({
        final_decision: "block",
        control_mode: "inline_prevented",
        reason_code: "customer_data_to_public_ai",
      }),
  });

  await assert.rejects(
    () =>
      client.withLlmAuthorization(
        {
          ai_system_id: "internal-assistant",
          actor_type: "human",
          actor_id: "user-1",
          prompt: "Customer email jane@example.com",
          provider: "openai",
        },
        async () => {
          executed = true;
          return { id: "model-response" };
        },
      ),
    HawkActionBlockedError,
  );

  assert.equal(executed, false);
});

test("withMcpAuthorization executes the tool callback when Hawk allows", async () => {
  const client = new HawkClient({
    apiUrl: "http://hawk.local:8000",
    tenantId: "tenant-1",
    accessToken: "token-1",
    fetchImpl: async () =>
      jsonResponse({
        final_decision: "allow",
        control_mode: "inline_allowed",
        evidence_bundle_id: "evidence-2",
      }),
  });

  const result = await client.withMcpAuthorization(
    {
      ai_system_id: "developer-agent",
      actor_id: "agent-1",
      capability_token: "capability-token",
      action: "read_file",
      resource: "repo:///settings/guide",
      tool_name: "read_file",
    },
    async () => ({ content: "safe read-only result" }),
  );

  assert.equal(result.hawk.final_decision, "allow");
  assert.deepEqual(result.result, { content: "safe read-only result" });
});

test("guardDataTransfer blocks require_justification until caller records justification", async () => {
  const client = new HawkClient({
    apiUrl: "http://hawk.local:8000",
    tenantId: "tenant-1",
    accessToken: "token-1",
    fetchImpl: async () =>
      jsonResponse({
        decision: "require_justification",
        control_mode: "inline_prevented",
        reason_code: "business_data_to_public_ai",
        justification_required: true,
      }),
  });

  await assert.rejects(
    () =>
      client.guardDataTransfer({
        copy_context: {
          copied_text_hash: "hash-1",
          copied_text_preview_redacted: "Customer email: [email]",
        },
        paste_context: {
          destination_domain: "chatgpt.com",
          destination_surface_type: "public_ai",
        },
      }),
    (error) => {
      assert.ok(error instanceof HawkActionBlockedError);
      assert.equal(error.decision, "require_justification");
      assert.equal(error.reasonCode, "business_data_to_public_ai");
      return true;
    },
  );
});

test("hawkThreatFindings extracts OWASP/ATLAS threats from guardian_results", () => {
  const response = {
    final_decision: "block",
    guardian_results: [
      { guardian_id: "sensitive_data_guard", decision: "block", threat_types: ["sensitive_data_leakage"] },
      {
        guardian_id: "prompt_injection_direct_override_guard",
        decision: "block",
        threat_types: ["prompt_injection"],
        framework_refs: { owasp_llm: "LLM01:2025 Prompt Injection", mitre_atlas: "AML.T0051 LLM Prompt Injection" },
      },
    ],
  };
  const findings = hawkThreatFindings(response);
  assert.equal(findings.length, 2);
  const types = hawkThreatTypes(response).sort();
  assert.deepEqual(types, ["prompt_injection", "sensitive_data_leakage"]);
  const injection = findings.find((f) => f.threatTypes.includes("prompt_injection"));
  assert.equal(injection.frameworks.mitre_atlas, "AML.T0051 LLM Prompt Injection");
});

test("hawkThreatFindings returns empty for a clean response", () => {
  assert.deepEqual(hawkThreatFindings({ final_decision: "allow", guardian_results: [] }), []);
  assert.deepEqual(hawkThreatTypes({ final_decision: "allow" }), []);
});

test("assertToolSafe throws on a poisoned tool scan", () => {
  assert.throws(
    () => assertToolSafe({ tool_poisoning_decision: "block", trust_status: "blocked" }),
    HawkActionBlockedError,
  );
  assert.doesNotThrow(() => assertToolSafe({ tool_poisoning_decision: "allow", trust_status: "approved" }));
});

test("constructs endpoint mode without API URL, tenant, or bearer credentials", () => {
  assert.doesNotThrow(() => new HawkEndpointClient(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-constructor-${process.pid}.sock`),
  )));
});

test("endpoint SDK refuses to start without a managed device-key pin", () => {
  assert.throws(
    () => new HawkEndpointClient({
      mode: "endpoint",
      endpointSocketPath: "/private/tmp/hawk-agent.sock",
    }),
    (error) => error?.name === "HawkEndpointClientError",
  );
});

test("root browser/backend entry has no Node endpoint transport dependency", async () => {
  const [clientSource, indexSource, packageSource, nodeClientSource] = await Promise.all([
    readFile(new URL("../dist/client.js", import.meta.url), "utf8"),
    readFile(new URL("../dist/index.js", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../dist/node-client.js", import.meta.url), "utf8"),
  ]);

  for (const source of [clientSource, indexSource]) {
    assert.equal(source.includes("endpoint.js"), false);
    assert.equal(source.includes("node:"), false);
  }
  assert.equal(nodeClientSource.includes('from "./endpoint.js"'), true);
  assert.equal(JSON.parse(packageSource).exports["./endpoint"].import, "./dist/node-client.js");
});

test("root SDK entry bundles for a browser target without Node polyfills", async (t) => {
  const outputPath = await mkdtemp(join(tmpdir(), "hawk-sdk-browser-bundle-"));
  t.after(() => rm(outputPath, { recursive: true, force: true }));
  const webpackModule = await import("../../../apps/web/node_modules/next/dist/compiled/webpack/webpack.js");
  const compiled = webpackModule.default ?? webpackModule;
  compiled.init();

  const stats = await new Promise((resolve, reject) => {
    compiled.webpack({
      mode: "production",
      target: "web",
      entry: fileURLToPath(new URL("../dist/index.js", import.meta.url)),
      output: { path: outputPath, filename: "hawk-sdk-browser.js" },
      optimization: { minimize: false },
    }, (error, result) => {
      if (error) reject(error);
      else resolve(result);
    });
  });
  const report = stats.toJson({ all: false, errors: true, warnings: true });
  assert.deepEqual(report.errors, []);
  assert.deepEqual(report.warnings, []);
});

test("backend-format data transfer is rejected explicitly in endpoint mode", async () => {
  const client = new HawkEndpointClient(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-no-transfer-${process.pid}.sock`),
  ));

  assert.throws(
    () => client.dataTransferCheck({
      copy_context: { copied_text_hash: "sha256:test" },
      paste_context: { destination_domain: "chatgpt.com" },
    }),
    (error) => error?.message === "HawkClient backend method requires backend mode",
  );
  await assert.rejects(
    () => client.endpointDataTransfer({
      copy_context: { copied_text_hash: "sha256:test" },
      paste_context: { destination_domain: "chatgpt.com" },
    }),
    (error) => error?.message === "endpointDataTransfer requires direct copied_text",
  );
});

test("developer-agent endpoint binding requires an explicit capability token", async () => {
  const client = new HawkEndpointClient(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-no-capability-${process.pid}.sock`),
  ));

  await assert.rejects(
    () => client.endpointDeveloperAgent({
      ai_system_id: "codex-agent",
      actor_id: "agent-1",
      capability_token: "",
      action: "repository.write",
      resource: "repo://payments/auth.ts",
    }),
    (error) => error?.message === "endpointDeveloperAgent requires capability_token",
  );
});

test("endpoint request size is bounded before IPC connection", async () => {
  const client = new HawkEndpointClient(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-no-oversize-${process.pid}.sock`), {
    endpointMaxRequestBytes: 128,
  }));

  await assert.rejects(
    () => client.endpointLlm({
      ai_system_id: "test",
      actor_type: "human",
      actor_id: "user-1",
      prompt: "x".repeat(1024),
    }),
    (error) => error?.name === "HawkEndpointClientError"
      && error?.message === "Hawk endpoint authorization failed",
  );
});

test("monitor decisions are truthful and cannot pass guarded execution", async () => {
  const transport = new HawkEndpointTransport(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-monitor-${process.pid}.sock`),
  ));
  transport.exchange = async (request) => ({
    ok: true,
    request_id: request.request_id,
    action: "allow",
    control_mode: "monitor_would_block",
    reason: "sensitive_data_policy",
    detail: { would_action: "block" },
  });

  const decision = await transport.evaluate("llm", {
    ai_system_id: "bank-assistant",
    actor_type: "human",
    actor_id: "user-1",
    prompt: "monitor this",
  });
  assert.equal(decision.final_decision, "allow");
  assert.equal(decision.endpoint_authorized, false);
  assert.equal(decision.decision_source, "endpoint_agent_monitor");
  assert.equal(decision.would_decision, "block");
  assert.throws(() => assertEndpointAuthorized(decision), HawkEndpointAuthorizationRequiredError);
  assert.throws(
    () => assertEndpointAuthorized({
      ...decision,
      endpoint_authorized: true,
      decision_source: "backend",
    }),
    HawkEndpointAuthorizationRequiredError,
  );

  let executed = false;
  const client = new HawkEndpointClient(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-monitor-client-${process.pid}.sock`),
  ));
  client.endpointPromise = Promise.resolve(transport);
  await assert.rejects(
    () => client.withLlmAuthorization({
      ai_system_id: "bank-assistant",
      actor_type: "human",
      actor_id: "user-1",
      prompt: "monitor this",
    }, async () => {
      executed = true;
    }),
    HawkEndpointAuthorizationRequiredError,
  );
  assert.equal(executed, false);
});

test("signed fail-secure warnings cannot authorize protected callbacks", async () => {
  const transport = new HawkEndpointTransport(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-fail-secure-${process.pid}.sock`),
  ));
  transport.exchange = async (request) => ({
    ok: true,
    request_id: request.request_id,
    action: "warn",
    control_mode: "warned",
    reason: "fail_secure:warn:HawkApiError",
    source: "fail_secure_default",
  });

  const decision = await transport.evaluate("developer_agent", {
    ai_system_id: "bank-agent",
    actor_id: "agent-1",
    capability_token: "short-lived-token",
    action: "email.send",
    resource: "gmail://outbound",
  });
  assert.equal(decision.final_decision, "warn");
  assert.equal(decision.endpoint_authorized, false);
  assert.equal(decision.decision_source, "endpoint_agent_fail_secure");
  assert.throws(() => assertEndpointAuthorized(decision), HawkEndpointAuthorizationRequiredError);

  let executed = false;
  const client = new HawkEndpointClient(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-fail-secure-client-${process.pid}.sock`),
  ));
  client.endpointPromise = Promise.resolve(transport);
  await assert.rejects(
    () => client.withLlmAuthorization({
      ai_system_id: "bank-agent",
      actor_type: "agent",
      actor_id: "agent-1",
      prompt: "synthetic prompt",
    }, async () => {
      executed = true;
    }),
    HawkEndpointAuthorizationRequiredError,
  );
  assert.equal(executed, false);
});

test("enforce-mode endpoint block remains authorized and blocking", async () => {
  const transport = new HawkEndpointTransport(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-enforce-${process.pid}.sock`),
  ));
  transport.exchange = async (request) => ({
    ok: true,
    request_id: request.request_id,
    action: "block",
    control_mode: "inline_prevented",
    reason: "repository_write_denied",
    source: "backend",
  });

  const decision = await transport.evaluate("developer_agent", {
    ai_system_id: "codex-agent",
    actor_id: "agent-1",
    capability_token: "short-lived-token",
    action: "repository.write",
    resource: "repo://payments/auth.ts",
  });
  assert.equal(decision.final_decision, "block");
  assert.equal(decision.endpoint_authorized, true);
  assert.equal(decision.decision_source, "endpoint_agent");
  assert.doesNotThrow(() => assertEndpointAuthorized(decision));
  assert.throws(() => assertHawkAllowed(decision), HawkActionBlockedError);
});

test("generic SDK keeps scope fail closed even when the agent reports backend proof", async () => {
  const transport = new HawkEndpointTransport(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-scope-${process.pid}.sock`),
  ));
  transport.exchange = async (request) => ({
    ok: true,
    request_id: request.request_id,
    action: "scope",
    control_mode: "scoped",
    reason: "limited_repository_scope",
    source: "backend",
    constraints_enforced: true,
    detail: { constraints_enforced: true },
  });

  const decision = await transport.evaluate("developer_agent", {
    ai_system_id: "codex-agent",
    actor_id: "agent-1",
    capability_token: "short-lived-token",
    action: "repository.read",
    resource: "repo://payments",
  });
  assert.equal(decision.final_decision, "block");
  assert.equal(decision.control_mode, "inline_prevented");
});

test("nested raw content and capability tokens cannot enter endpoint receipts", async () => {
  const nestedPrompt = "nested-secret-prompt-token";
  const nestedCapability = "nested-capability-token";
  const transport = new HawkEndpointTransport(endpointModeOptions(
    join(tmpdir(), `hawk-sdk-nested-${process.pid}.sock`),
  ));
  transport.exchange = async (request) => ({
    ok: true,
    request_id: request.request_id,
    action: "block",
    control_mode: "inline_prevented",
    reason: nestedPrompt,
    evidence_ref: nestedCapability,
    source: "backend",
  });

  const decision = await transport.evaluate("sdk", {
    ai_system_id: "bank-assistant",
    actor_id: "user-1",
    context: {
      prompt: nestedPrompt,
      credentials: [{ capability_token: nestedCapability }],
    },
  });
  const serialized = JSON.stringify(decision);
  assert.equal(serialized.includes(nestedPrompt), false);
  assert.equal(serialized.includes(nestedCapability), false);
});

test("endpoint mode requires no backend credentials and returns the same canonical LLM/SDK decision", async (t) => {
  const endpoint = await startEndpoint(({ request, reply }) => reply({
    ok: true,
    request_id: request.request_id,
    action: "allow",
    control_mode: "inline_allowed",
    reason: "approved",
    evidence_ref: `evidence-${request.surface}`,
  }));
  t.after(endpoint.close);
  const client = new HawkEndpointClient(endpointModeOptions(endpoint.path, {
    clientName: "bank-app",
    clientVersion: "3.2.1",
  }));
  const payload = {
    ai_system_id: "bank-assistant",
    actor_type: "human",
    actor_id: "user-1",
    prompt: "Summarize approved public controls",
    pre_action: false,
    inline_authorized: true,
    surface: "mcp",
    client_metadata: { name: "spoofed-client" },
  };

  const llm = await client.endpointLlm(payload);
  const sdk = await client.endpointSdk(payload);
  const canonical = (value) => ({
    final_decision: value.final_decision,
    control_mode: value.control_mode,
    reason_code: value.reason_code,
    endpoint_authorized: value.endpoint_authorized,
  });

  assert.deepEqual(canonical(llm), canonical(sdk));
  assert.deepEqual(canonical(llm), {
    final_decision: "allow",
    control_mode: "inline_allowed",
    reason_code: "approved",
    endpoint_authorized: true,
  });
  assert.equal(endpoint.requests[0].protocol_version, 1);
  assert.equal(endpoint.requests[0].op, "evaluate");
  assert.equal(endpoint.requests[0].surface, "llm");
  assert.equal(endpoint.requests[1].surface, "sdk");
  for (const request of endpoint.requests) {
    assert.equal(request.pre_action, undefined);
    assert.equal(request.inline_authorized, undefined);
    assert.equal(request.client_metadata.name, "bank-app");
    assert.equal(request.client_metadata.version, "3.2.1");
    assert.equal(request.client_metadata.runtime, "node");
    assert.equal(request.process_metadata.pid, process.pid);
  }
});

test("endpoint developer-agent write is blocked before caller execution", async (t) => {
  const endpoint = await startEndpoint(({ request, reply }) => reply({
    ok: true,
    request_id: request.request_id,
    action: "block",
    control_mode: "inline_prevented",
    reason: "repository_write_denied",
    evidence_ref: "developer-receipt-1",
  }));
  t.after(endpoint.close);
  const client = new HawkEndpointClient(endpointModeOptions(endpoint.path));

  const decision = await client.endpointDeveloperAgent({
    ai_system_id: "codex-agent",
    actor_id: "agent-1",
    capability_token: "short-lived-capability-token",
    action: "repository.write",
    resource: "repo://payments/auth.ts",
    tool_name: "write_file",
  });

  assert.equal(decision.final_decision, "block");
  assert.equal(decision.control_mode, "inline_prevented");
  assert.throws(() => assertHawkAllowed(decision), HawkActionBlockedError);
  assert.equal(endpoint.requests[0].surface, "developer_agent");
  assert.equal(endpoint.requests[0].action, "repository.write");
  assert.equal(JSON.stringify(decision).includes("short-lived-capability-token"), false);
});

test("endpoint Foundry method binds provider attribution internally", async (t) => {
  const endpoint = await startEndpoint(({ request, reply }) => reply({
    ok: true,
    request_id: request.request_id,
    action: "allow",
    control_mode: "inline_allowed",
    reason: "approved_foundry_call",
  }));
  t.after(endpoint.close);
  const client = new HawkEndpointClient(endpointModeOptions(endpoint.path));

  const decision = await client.endpointFoundry({
    ai_system_id: "foundry-app",
    actor_type: "service",
    actor_id: "svc-foundry",
    prompt: "Summarize the approved policy",
    provider: "caller-controlled-provider",
  });

  assert.equal(decision.final_decision, "allow");
  assert.equal(endpoint.requests[0].surface, "foundry");
  assert.equal(endpoint.requests[0].provider, "microsoft_foundry");
  assert.equal(endpoint.requests[0].foundry_attribution, "sdk_endpoint_binding");
});

test("endpoint data-transfer block returns a content-free receipt", async (t) => {
  const secret = "sk-test-this-must-not-enter-the-receipt";
  const endpoint = await startEndpoint(({ request, reply }) => reply({
    ok: true,
    request_id: request.request_id,
    action: "block",
    control_mode: "inline_prevented",
    reason: secret,
    evidence_ref: "transfer-receipt-1",
  }));
  t.after(endpoint.close);
  const client = new HawkEndpointClient(endpointModeOptions(endpoint.path));

  const decision = await client.endpointDataTransfer({
    copied_text: secret,
    source_domain: "internal.bank",
    destination_domain: "chatgpt.com",
    destination_app: "ChatGPT",
    pre_action: false,
  });

  assert.equal(decision.final_decision, "block");
  assert.equal(endpoint.requests[0].surface, "data_transfer");
  assert.equal(endpoint.requests[0].copied_text, secret);
  assert.equal(endpoint.requests[0].pre_action, undefined);
  assert.equal(JSON.stringify(decision).includes(secret), false);
  assert.equal("prompt" in decision.receipt, false);
  assert.equal("copied_text" in decision.receipt, false);
});

test("endpoint transport fails closed when unavailable, malformed, oversized, or uncorrelated", async (t) => {
  const malformed = await startEndpoint(({ socket }) => socket.end("not-json\n"));
  const oversized = await startEndpoint(({ socket }) => socket.end(`${"x".repeat(2048)}\n`));
  const uncorrelated = await startEndpoint(({ reply }) => reply({
    ok: true,
    request_id: "wrong-request",
    action: "allow",
    control_mode: "inline_allowed",
  }));
  t.after(malformed.close);
  t.after(oversized.close);
  t.after(uncorrelated.close);
  const cases = [
    new HawkEndpointClient(endpointModeOptions(
      join(tmpdir(), `missing-hawk-sdk-${process.pid}.sock`), {
      endpointTimeoutMs: 30,
    })),
    new HawkEndpointClient(endpointModeOptions(malformed.path)),
    new HawkEndpointClient(endpointModeOptions(oversized.path, {
      endpointMaxResponseBytes: 256,
    })),
    new HawkEndpointClient(endpointModeOptions(uncorrelated.path)),
  ];

  for (const client of cases) {
    await assert.rejects(
      () => client.endpointLlm({
        ai_system_id: "test",
        actor_type: "human",
        actor_id: "user-1",
        prompt: "hello",
      }),
      (error) => error?.name === "HawkEndpointClientError"
        && error?.message === "Hawk endpoint authorization failed",
    );
  }
});

test("endpoint transport rejects unknown and non-enforceable decisions", async (t) => {
  const endpoint = await startEndpoint(({ request, reply }) => {
    const action = request.prompt;
    reply({
      ok: true,
      request_id: request.request_id,
      action,
      control_mode: action === "scope" ? "scoped" : "inline_prevented",
      reason: `test_${action}`,
    });
  });
  t.after(endpoint.close);
  const client = new HawkEndpointClient(endpointModeOptions(endpoint.path));

  for (const action of ["unknown", "hold_for_approval", "review", "redact", "scope"]) {
    if (action === "unknown") {
      await assert.rejects(
        () => client.endpointSdk({
          ai_system_id: "test",
          actor_type: "human",
          actor_id: "user-1",
          prompt: action,
        }),
        (error) => error?.name === "HawkEndpointClientError",
      );
      continue;
    }
    const decision = await client.endpointSdk({
      ai_system_id: "test",
      actor_type: "human",
      actor_id: "user-1",
      prompt: action,
    });
    assert.equal(decision.final_decision, "block", action);
    assert.equal(decision.endpoint_authorized, true, action);
  }
});

test("endpoint receipt never retains a raw LLM prompt", async (t) => {
  const rawPrompt = "Confidential merger plan code-name NIGHTFALL";
  const endpoint = await startEndpoint(({ request, reply }) => reply({
    ok: true,
    request_id: request.request_id,
    action: "warn",
    control_mode: "warned",
    reason: "sensitive_context",
    evidence_ref: "llm-receipt-1",
  }));
  t.after(endpoint.close);
  const client = new HawkEndpointClient(endpointModeOptions(endpoint.path));

  const decision = await client.endpointLlm({
    ai_system_id: "bank-assistant",
    actor_type: "human",
    actor_id: "user-1",
    prompt: rawPrompt,
  });

  assert.equal(endpoint.requests[0].prompt, rawPrompt);
  assert.equal(JSON.stringify(decision).includes(rawPrompt), false);
  assert.deepEqual(Object.keys(decision.receipt).sort(), [
    "client_name",
    "client_version",
    "control_mode",
    "decision",
    "evidence_ref",
    "process_id",
    "reason_code",
    "request_id",
    "surface",
  ]);
});

test("endpoint registration is correlated, signed, bounded, and never implies inline coverage", async (t) => {
  const endpoint = await startEndpoint(({ request, reply }) => reply({
    ok: true,
    request_id: request.request_id,
    status: "registered",
    registration_id: "registration-1",
    evidence_state: "sdk_self_registration",
    control_state: "monitor_only",
    active_integration_transport: "composio",
    evidence_ref: "evidence-registration-1",
  }));
  t.after(endpoint.close);
  const client = new HawkEndpointClient(endpointModeOptions(endpoint.path, {
    clientName: "agent-os",
    clientVersion: "1.0.0",
  }));

  const result = await client.endpointRegisterAgent({
    agent_id: "agent-os-local",
    agent_name: "Agent OS",
    agent_version: "1.0.0",
    runtime_provider: "node",
    model_provider: "ollama",
    model_name: "qwen3.5:9b",
    models: ["qwen3.5:9b"],
    detected_tools: ["web_search", "GMAIL_FETCH_EMAILS", "GMAIL_CREATE_DRAFT", "GMAIL_SEND_EMAIL"],
    detected_actions: ["web.read", "email.read", "email.draft.create", "email.send"],
    detected_privileges: ["internet", "mailbox.read", "mailbox.write"],
    listening_ports: [4000, 5174],
    integration_transports: [
      {
        capability: "gmail",
        transport: "composio",
        destination_domain: "backend.composio.dev",
        active: true,
        evidence_basis: "runtime_configuration",
      },
      {
        capability: "gmail",
        transport: "google_direct",
        destination_domain: "gmail.googleapis.com",
        active: false,
        evidence_basis: "supported_binding",
      },
    ],
    active_integration_transport: "composio",
    control_binding: {
      mode: "enforce",
      pre_action_surfaces: ["llm", "developer_agent"],
    },
  });

  assert.deepEqual(result, {
    status: "registered",
    registration_id: "registration-1",
    evidence_state: "sdk_self_registration",
    control_state: "monitor_only",
    active_integration_transport: "composio",
    evidence_ref: "evidence-registration-1",
  });
  assert.equal(endpoint.requests[0].op, "register_agent");
  assert.equal(endpoint.requests[0].protocol_version, 1);
  assert.equal(endpoint.requests[0].client_metadata.name, "agent-os");
  assert.equal(endpoint.requests[0].process_metadata.pid, process.pid);
  assert.equal(endpoint.requests[0].active_integration_transport, "composio");
  assert.equal(endpoint.requests[0].control_state, undefined);
});

test("endpoint registration rejects secret-bearing manifests before IPC", async () => {
  const client = new HawkEndpointClient(endpointModeOptions(
    join(tmpdir(), `unused-hawk-registration-${process.pid}.sock`),
  ));

  await assert.rejects(
    () => client.endpointRegisterAgent({
      agent_id: "agent-os-local",
      agent_name: "Agent OS",
      agent_version: "1.0.0",
      runtime_provider: "node",
      model_provider: "ollama",
      model_name: "qwen3.5:9b",
      models: [],
      detected_tools: [],
      detected_actions: [],
      detected_privileges: [],
      listening_ports: [],
      integration_transports: [],
      active_integration_transport: "unknown",
      control_binding: { mode: "enforce", pre_action_surfaces: [] },
      token: "must-never-leave-process",
    }),
    (error) => error?.name === "HawkEndpointClientError",
  );
});

async function startEndpoint(handler) {
  const directory = await mkdtemp(join(tmpdir(), "hawk-sdk-endpoint-"));
  await chmod(directory, 0o700);
  const path = join(directory, "agent.sock");
  const requests = [];
  const server = createServer((socket) => {
    socket.setEncoding("utf8");
    let buffered = "";
    socket.on("data", (chunk) => {
      buffered += chunk;
      const newline = buffered.indexOf("\n");
      if (newline < 0) return;
      const request = JSON.parse(buffered.slice(0, newline));
      requests.push(request);
      handler({
        request,
        socket,
        reply: (response) => socket.end(`${JSON.stringify(signedEndpointBrokerResponse({ source: "backend", ...response }))}\n`),
      });
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, resolve);
  });
  await chmod(path, 0o600);
  return {
    path,
    requests,
    close: async () => {
      await new Promise((resolve) => server.close(resolve));
      await rm(directory, { recursive: true, force: true });
    },
  };
}
