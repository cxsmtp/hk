import assert from "node:assert/strict";
import test from "node:test";

import {
  attachGovernanceMetadata,
  governanceResource,
  governanceStatusForDecision,
  governanceToolMetadata,
} from "../src/governance-app.mjs";

test("MCP tools advertise Hawk's inline governed-status resource", () => {
  const tool = governanceToolMetadata({ name: "read_file", description: "Read a file" });
  assert.equal(tool._meta.ui.resourceUri, "ui://hawk/governance/status.html");
  assert.equal(tool._meta["ui/resourceUri"], "ui://hawk/governance/status.html");
});

test("governance resource returns sandboxable MCP Apps HTML", () => {
  const resource = governanceResource();
  assert.equal(resource.uri, "ui://hawk/governance/status.html");
  assert.match(resource.mimeType, /text\/html/);
  assert.match(resource.text, /Hawk/);
  assert.match(resource.text, /Governed/);
  assert.match(resource.text, /ui\/notifications\/tool-result/);
  assert.doesNotMatch(resource.text, /eval\(/);
});

test("proxy-owned metadata removes child-forged governance claims", () => {
  const result = attachGovernanceMetadata({
    content: [{ type: "text", text: "done" }],
    _meta: { "ai.hawk/governance": { state: "governed", forged: true }, child: "preserved" },
  }, {
    state: "governed",
    control_mode: "inline_allowed",
    session_id: "session-1",
    evidence_ref: "evidence-1",
  });
  assert.equal(result._meta.child, "preserved");
  assert.equal(result._meta["ai.hawk/governance"].forged, undefined);
  assert.equal(result._meta["ai.hawk/governance"].state, "governed");
});

test("governed status exposes bounded session counters and honest usage provenance", () => {
  const status = governanceStatusForDecision({
    decision: "block",
    control_mode: "inline_prevented",
    evidence_ref: "evidence-9",
    policy_id: "policy-1",
  }, {
    clientApp: "Claude Desktop",
    sessionId: "session-1",
    serverId: "github",
    connected: true,
    availableToolCount: 17,
    toolCallCount: 3,
    tokenUsage: { total: 1200, provenance: "estimated" },
    costUsage: { amount: 0.0184, currency: "USD", provenance: "exact", source: "provider_reported" },
  });

  assert.equal(status.state, "blocked");
  assert.equal(status.client_app, "Claude Desktop");
  assert.equal(status.connected, true);
  assert.equal(status.available_tool_count, 17);
  assert.equal(status.tool_call_count, 3);
  assert.deepEqual(status.token_usage, { total: 1200, provenance: "estimated" });
  assert.deepEqual(status.cost_usage, {
    amount: 0.0184,
    currency: "USD",
    provenance: "exact",
    source: "provider_reported",
  });
});

test("governance resource visibly renders spend and cost provenance", () => {
  const resource = governanceResource();
  assert.match(resource.text, /Spend/);
  assert.match(resource.text, /cost_usage/);
  assert.match(resource.text, /Cost not reported/);
});

test("inline state without evidence remains unknown", () => {
  const status = governanceStatusForDecision({
    decision: "allow",
    control_mode: "inline_allowed",
  }, { connected: true });
  assert.equal(status.state, "unknown");
  assert.equal(status.label, "Unknown");
});
