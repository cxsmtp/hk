import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const routes = ["observe", "assets", "protect", "validate", "deploy", "evidence"];

test("approved lifecycle routes are real pages", () => {
  for (const route of routes) {
    const url = new URL(`../src/app/${route}/page.tsx`, import.meta.url);
    assert.equal(existsSync(url), true, `${route} route missing`);
    assert.match(readFileSync(url, "utf8"), /<AppShell>/);
  }
});

test("Observe presents Activity and governed sessions with truthful token provenance and trace access", () => {
  const source = readFileSync(new URL("../src/components/lifecycle/observe-workspace.tsx", import.meta.url), "utf8");
  assert.match(source, /title="Activity"/);
  assert.match(source, /Visible sessions/);
  assert.match(source, /deriveGovernanceState/);
  assert.match(source, /deriveTokenUsage/);
  assert.match(source, /Exact|Estimated|Unknown/);
  assert.match(source, /surface/i);
  assert.match(source, /trace/i);
  assert.match(source, /MCP/);
  assert.match(source, /LLM/);
  assert.match(source, /Governed spend/);
  assert.match(source, /Cost not reported/);
  assert.match(source, /Input tokens/);
  assert.match(source, /Output tokens/);
  for (const label of ["Uploads", "Warnings", "Failures", "Loaded", "Load older activity", "Files attached"]) assert.match(source, new RegExp(label));
  assert.match(source, /runtime_event_id: requestEventId/);
  assert.match(source, /page: pageNumber, page_size: 100/);
  assert.match(source, /mergeActivityPages\(runtimeResult.value\)/);
  assert.match(source, /setLoadedPages\(\(pages\) => pages \+ 1\)/);
});

test("Assets implements the approved identity-to-evidence journey", () => {
  const source = readFileSync(new URL("../src/components/lifecycle/assets-workspace.tsx", import.meta.url), "utf8");
  for (const label of ["Owner", "Delegated authority", "Tools & data", "Risky path", "Recommended policy", "Evidence"]) {
    assert.match(source, new RegExp(label, "i"));
  }
  assert.match(source, /Promise\.allSettled/);
});

test("Protect implements the five-step policy workflow and real publish API", () => {
  const source = readFileSync(new URL("../src/components/lifecycle/policy-builder.tsx", import.meta.url), "utf8");
  for (const step of ["Intent", "Scope", "Action", "Validate", "Publish"]) {
    assert.match(source, new RegExp(step));
  }
  assert.match(source, /createPolicyVersion/);
  assert.match(source, /updatePolicyVersionScopedRules/);
  assert.match(source, /observed/i);
  assert.match(source, /Confirm enforcement/i);
});

test("Validate, Deploy and Evidence retain conservative control distinctions", () => {
  const validate = readFileSync(new URL("../src/components/lifecycle/validate-workspace.tsx", import.meta.url), "utf8");
  const deploy = readFileSync(new URL("../src/components/lifecycle/deploy-workspace.tsx", import.meta.url), "utf8");
  const evidence = readFileSync(new URL("../src/components/lifecycle/evidence-workspace.tsx", import.meta.url), "utf8");
  assert.match(validate, /Simulation|Control Validation/);
  assert.match(validate, /listSimulationDefinitions/);
  assert.match(validate, /runSimulation/);
  assert.match(validate, /Evidence receipt/);
  assert.match(validate, /Run selected test/);
  assert.match(validate, /Policy decision/);
  assert.match(deploy, /Protected|Partially protected|Monitor only|Outside control|Unknown/);
  assert.match(deploy, /policy_enforced_count === surface\.observed_event_count/);
  assert.match(evidence, /freshness|Evidence/i);
  assert.match(validate, /Promise\.allSettled/);
  assert.match(deploy, /Promise\.allSettled/);
});
