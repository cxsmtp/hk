import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

async function loadModule() {
  const source = readFileSync(
    new URL("../src/lib/agent-runtime-profile.ts", import.meta.url),
    "utf8",
  );
  const result = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    reportDiagnostics: true,
  });
  assert.deepEqual(
    (result.diagnostics || []).filter(
      (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error,
    ),
    [],
  );
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

test("projects endpoint-bound agent evidence without inflating authorization", async () => {
  const { deriveAgentRuntimeProfile } = await loadModule();
  const view = deriveAgentRuntimeProfile({
    control_binding_state: "monitor_only",
    evidence_basis: "sdk_self_registration",
    agent_runtime_profile: {
      agent_id: "agent-os-local",
      agent_name: "Agent OS",
      runtime_provider: "node",
      model_provider: "ollama",
      model_name: "qwen3.5:9b",
      models: ["qwen3.5:9b", "qwen2.5:14b"],
      tools: ["GMAIL_FETCH_EMAILS", "GMAIL_SEND_EMAIL"],
      actions: ["email.read", "email.send"],
      privileges: ["mailbox.read", "mailbox.write"],
      listening_ports: [4000, 5174],
      active_integration_transport: "composio",
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
      control_binding: {
        mode: "enforce",
        pre_action_surfaces: ["llm", "developer_agent"],
      },
    },
  });

  assert.equal(view?.agentName, "Agent OS");
  assert.equal(view?.activeTransport, "composio");
  assert.equal(view?.controlState, "monitor_only");
  assert.equal(view?.requestedMode, "enforce");
  assert.equal(view?.evidenceBasis, "sdk_self_registration");
  assert.deepEqual(view?.preActionSurfaces, ["llm", "developer_agent"]);
  assert.deepEqual(view?.integrations.map((item) => [item.transport, item.active]), [
    ["composio", true],
    ["google_direct", false],
  ]);
});

test("returns no runtime card when the entity has no agent registration evidence", async () => {
  const { deriveAgentRuntimeProfile } = await loadModule();
  assert.equal(deriveAgentRuntimeProfile({}), null);
  assert.equal(deriveAgentRuntimeProfile({ agent_runtime_profile: [] }), null);
});
