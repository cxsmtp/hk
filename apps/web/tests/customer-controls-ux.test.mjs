import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";
import { runInNewContext } from "node:vm";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("customer controls expose event-first activity and evidence sections", () => {
  const source = read("../src/components/lifecycle/observe-workspace.tsx");
  for (const label of ["When", "Who / using what", "Action", "Target", "Hawk decision", "Outcome", "What happened", "Who was involved", "Request and result", "Why Hawk acted", "Related activity", "Capture and retention", "Detailed evidence unavailable"]) assert.match(source, new RegExp(label.replace(/[\\/]/g, "\\$&")));
  assert.match(source, /DetailDrawer/);
  assert.match(source, /searchActivityAudit/);
});

test("deployment and policy surfaces preserve truthful customer controls", () => {
  const deploy = read("../src/components/lifecycle/deploy-workspace.tsx");
  const policy = read("../src/components/lifecycle/policy-builder.tsx");
  const integrations = read("../src/components/integrations/connector-control-room.tsx");
  const integrationsPage = read("../src/app/integrations/page.tsx");
  for (const label of ["Browser Extension", "MCP Gateway", "LLM Gateway", "Endpoint Agent"]) assert.match(deploy, new RegExp(label));
  for (const label of ["Applications", "Exact reported name", "Websites / domains", "AI providers", "Models", "MCP servers", "MCP tools", "Action types", "Operations", "Advanced event source context", "Broad scope"]) assert.ok(policy.includes(label), `missing ${label}`);
  for (const label of ["Connected sources", "What Hawk can observe", "What Hawk can control", "Integration status unavailable"]) assert.match(integrations, new RegExp(label));
  assert.match(integrationsPage, /GitHub/);
  assert.match(integrationsPage, /GitHub Cloud/);
  assert.match(integrationsPage, /GitHub Enterprise Server/);
  assert.match(integrationsPage, /Connect or manage GitHub/);
  assert.match(integrationsPage, /Choosing a repository prepares a draft; approval happens in Policies/);
  assert.ok(integrationsPage.includes('selectedSourceFlow.family === "github" ? ["A GitHub account owner'));
});

test("policies and simulations advertise capability indexes and unavailable states", () => {
  const policies = read("../src/app/policies/page.tsx");
  const simulations = read("../src/app/simulations/page.tsx");
  for (const label of ["Policy packs", "Assignments", "Running policies", "Scoped rules", "Simulations", "Validation coverage", "Unavailable"]) assert.match(policies, new RegExp(label));
  for (const label of ["Run Explorer", "Packs", "Definitions", "Framework Coverage", "Control Coverage", "Traceability", "No matching test is available", "Catalog administration", "Unavailable"]) assert.match(simulations, new RegExp(label));
});

test("simulation headline values follow the source that owns each metric", () => {
  const source = read("../src/app/simulations/page.tsx");
  const expression = source.match(/const sourceValue = ([^;]+);/)?.[1];
  assert.ok(expression);
  const javascript = ts.transpileModule(`const sourceValue = ${expression}; sourceValue`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const sourceValue = runInNewContext(javascript, { sourceStates: { definitions: "loaded", packs: "error", runs: "loaded", traceability: "error", catalogCoverage: "error" } });
  assert.equal(sourceValue("definitions", 0), 0);
  assert.equal(sourceValue("packs", 0), "Unavailable");
  assert.equal(sourceValue("runs", 3), 3);
  assert.equal(sourceValue("traceability", 0), "Unavailable");
  assert.equal(sourceValue("catalogCoverage", "0%"), "Unavailable");
  for (const [label, owner] of [["Definitions", "definitions"], ["Packs", "packs"], ["Runs", "runs"], ["Failed Runs", "runs"], ["Controls Traced", "traceability"], ["Execution Readiness", "catalogCoverage"]]) {
    assert.match(source, new RegExp(`label: "${label}", value: sourceValue\\("${owner}"`));
  }
  assert.match(source, /scenarioHint && sourceStates\.definitions === "loaded" && !scenarioMatch/);
  assert.match(source, /scenarioHint && sourceStates\.definitions === "error"/);
  assert.match(source, /sourceStates\.systems === "error"[\s\S]*?traceability: "error"/);
  assert.doesNotMatch(source, /sourceStates\.systems === "error"[\s\S]*?setTraceability\(\[\]\)/);
});
