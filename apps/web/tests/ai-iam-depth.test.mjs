import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const detailUrl = new URL("../src/app/ai-iam/agents/[id]/page.tsx", import.meta.url);
const graphUrl = new URL("../src/components/ai-iam/agent-touchpoint-graph.tsx", import.meta.url);

test("AI IAM agent detail exposes the required investigation domains", () => {
  assert.equal(existsSync(detailUrl), true);
  const source = readFileSync(detailUrl, "utf8");
  for (const label of ["Overview", "Runtime", "Touchpoints", "Blast Radius", "Actions", "Permissions", "Policies", "Findings", "Evidence"]) {
    assert.match(source, new RegExp(`>${label}<`));
  }
});

test("AI IAM reach explicitly separates configured, observed, and simulated evidence", () => {
  const source = readFileSync(detailUrl, "utf8");
  for (const label of ["Configured reach", "Observed reach", "Simulated reach"]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /No simulated reach evidence/);
});

test("AI IAM renders evidence-backed touchpoint and blast-radius detail", () => {
  assert.equal(existsSync(graphUrl), true);
  const graph = readFileSync(graphUrl, "utf8");
  assert.match(graph, /Evidence Complete/);
  assert.match(graph, /Observed Touchpoint Graph/);
  assert.match(graph, /Potential Blast Radius/);
});
