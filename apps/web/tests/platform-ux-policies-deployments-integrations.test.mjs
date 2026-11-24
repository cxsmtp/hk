import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

test("policy library puts actionable policy contracts ahead of secondary analytics", () => {
  const page = source("app/policies/page.tsx");
  assert.ok(page.indexOf("<PolicyPackPlatformWorkspace />") < page.indexOf("<ModuleReportPanel"));
  assert.match(page, /href="\/protect"[^>]*>.*Create policy/s);
  for (const capability of ["policy-assignments", "running-policies", "policy-tuning-tools", "scoped-policy-tools", "policy-pack-tools"]) {
    assert.match(page, new RegExp(capability));
  }
});

test("policy administration stays readable, closed by default, and hash-addressable", () => {
  const page = source("app/policies/page.tsx");
  const headerStart = page.indexOf("<PageHeader");
  const refreshIndex = page.search(/>\s*Refresh\s*<\/Button>/);
  const createIndex = page.indexOf('href="/protect"', headerStart);
  assert.ok(createIndex >= headerStart && createIndex < refreshIndex);

  const administrationStart = page.indexOf('<details id="policy-administration-tools"');
  assert.ok(administrationStart >= 0);
  const administrationOpen = page.slice(administrationStart, page.indexOf(">", administrationStart) + 1);
  assert.doesNotMatch(administrationOpen, /\bopen\b/);
  assert.match(page.slice(administrationStart, administrationStart + 400), /<summary[^>]*>Policy packs, assignments, and rollout<\/summary>/);

  for (const anchor of ["policy-assignments", "running-policies", "policy-tuning-tools", "scoped-policy-tools", "policy-pack-tools"]) {
    assert.match(page, new RegExp(`id="${anchor}"`));
  }
  assert.match(page, /function revealPolicyHashTarget/);
  assert.match(page, /ancestor instanceof HTMLDetailsElement\) ancestor\.open = true/);
  assert.match(page, /target\.scrollIntoView\(/);
  assert.match(page, /window\.addEventListener\("hashchange", revealPolicyHashTarget\)/);

  for (const oldCopy of ["Apply Pilot Safe Defaults", "Policy Contracts", "Policy library / contracts", "Seed a new governance contract"]) {
    assert.doesNotMatch(page, new RegExp(oldCopy.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(page, /Technical enforcement details/);
  assert.match(page, /Pack ID: \{p\.id\}/);
  const runningKpi = page.slice(page.indexOf('label: "Running Policy Versions"'), page.indexOf('label: "Runtime Mode"'));
  assert.match(runningKpi, /value: runningState === "error" \? "Unavailable" : running\?\.running_versions\.length/);
  assert.doesNotMatch(runningKpi, /value:\s*[^,\n]*enforced_policy_version_id/);
});

test("the policy builder retains its five steps, four decisions, and scoped selectors", () => {
  const page = source("components/lifecycle/policy-builder.tsx");
  for (const step of ["Intent", "Scope", "Action", "Validate", "Publish"]) assert.match(page, new RegExp(`"${step}"`));
  for (const decision of ["allow", "warn", "require_approval", "block"]) assert.match(page, new RegExp(`"${decision}"`));
  for (const selector of ["Applications", "Websites / domains", "MCP servers", "MCP tools"]) assert.match(page, new RegExp(selector));
  assert.match(page, /api\.createPolicyVersion/);
  assert.match(page, /api\.updatePolicyVersionScopedRules/);
});

test("deployment methods lead to their own setup and evidence locations", () => {
  const page = source("components/lifecycle/deploy-workspace.tsx");
  for (const anchor of ["browser-extension", "mcp-gateway", "llm-gateway", "endpoint-agent"]) {
    assert.match(page, new RegExp(`href: "/surface-coverage#${anchor}"`));
  }
  assert.match(page, /aria-label="Deployment methods"/);
  assert.match(page, /<details[^>]*>\s*<summary[^>]*>Technical deployment diagnostics/s);
  assert.match(page, /observed_event_count === 0\) return surface\.last_seen_at \? "No activity observed" : "Unknown"/);
  assert.doesNotMatch(page, /return "Not connected"/);
});

test("integrations show connection state before setup and provide direct connect actions", () => {
  const room = source("components/integrations/connector-control-room.tsx");
  const page = source("app/integrations/page.tsx");
  assert.ok(room.indexOf("{props.connectionGuide ?") < room.indexOf("<ConnectorFleet"));
  assert.match(room, /onConfigureProvider/);
  assert.match(room, /aria-label=\{`Connect \$\{friendlyProviderName\(provider\)\}`\}/);
  assert.doesNotMatch(room, /className="sr-only">Connect/);
  assert.match(room, /Manage connection/);
  assert.match(page, /providerDisplayName\(providerKey, providers\)/);
  assert.doesNotMatch(room, /\{readiness\.statusLabel\}<\/Badge>/);
});

test("monitoring keeps raw breakdowns in optional diagnostics", () => {
  const page = source("app/monitoring/page.tsx");
  assert.match(page, /<summary[^>]*>Technical telemetry breakdowns<\/summary>/);
  assert.match(page, /observed_provider_category_counts/);
  assert.match(page, /<OperationalState/);
});

test("governance keeps stale systems visible and puts the inventory action before summaries", () => {
  const page = source("app/governance/page.tsx");
  assert.match(page, /<OperationalState/);
  assert.doesNotMatch(page, /load\(\)\.catch\(\(\) => setSystems\(\[\]\)\)/);
  assert.ok(page.indexOf('title="AI Systems"') < page.indexOf("<KpiStrip"));
  assert.match(page, /<summary[^>]*>Framework mappings and evidence paths<\/summary>/);
  assert.doesNotMatch(page, /\/deployment\/surface-coverage/);
});

test("lifecycle routes expose honest source states without clearing stale evidence", () => {
  const maturity = source("components/lifecycle/maturity-curve-workspace.tsx");
  const simulations = source("app/simulations/page.tsx");
  const validation = source("app/validation/coverage/page.tsx");
  const jobs = source("app/ops/jobs/page.tsx");
  assert.match(maturity, /<OperationalState/);
  assert.doesNotMatch(maturity, /setOverview\(null\);\s*setDetail\(null\);/);
  assert.match(simulations, /<OperationalState/);
  assert.doesNotMatch(simulations, /load\(querySystemId\)\.catch\(\(\) => \{[\s\S]{0,500}setDefs\(\[\]\)/);
  assert.match(validation, /<OperationalState/);
  assert.doesNotMatch(validation, /setControlExplorer\(null\);/);
  assert.match(jobs, /<OperationalState/);
  assert.doesNotMatch(jobs, /setItems\(\[\]\)/);
});

test("validate and protect retain the action-first controls", () => {
  const validate = source("components/lifecycle/validate-workspace.tsx");
  const protect = source("components/lifecycle/policy-builder.tsx");
  assert.ok(validate.indexOf('title="Control Test Center"') < validate.indexOf('>Run selected test</'));
  for (const step of ["Intent", "Scope", "Action", "Validate", "Publish"]) assert.match(protect, new RegExp(`"${step}"`));
  assert.match(protect, /api\.createPolicyVersion/);
});

test("governance keeps one compact metric strip and a single evidence disclosure", () => {
  const page = source("app/governance/page.tsx");
  assert.equal((page.match(/<KpiStrip/g) || []).length, 1);
  assert.doesNotMatch(page, /<ModuleReportPanel/);
  assert.equal((page.match(/<summary[^>]*>Framework mappings and evidence paths<\/summary>/g) || []).length, 1);
});

test("policy pack mapping separates control methods from product and source dimensions", () => {
  const workspace = source("components/lifecycle/policy-pack-platform-workspace.tsx");
  const deploy = source("components/lifecycle/deploy-workspace.tsx");
  for (const method of ["Browser Extension", "MCP Gateway", "LLM Gateway", "Endpoint Agent"]) {
    assert.match(deploy, new RegExp(method));
  }
  assert.match(workspace, /Source or product context/);
  assert.doesNotMatch(workspace, /Control method/);
  assert.match(workspace, /Product or source context/);
  for (const option of ["saas_api", "provider_native_hook", "mcp_gateway"]) {
    assert.match(workspace, new RegExp(`value=\"${option}\"`));
  }
});

test("secondary simulation tables remain discoverable after the run-first action", () => {
  const page = source("app/simulations/page.tsx");
  assert.ok(page.indexOf("Run one deterministic simulation") < page.indexOf("Executor Status"));
  assert.ok(page.indexOf("Run one deterministic simulation") < page.indexOf("Simulation Run Explorer"));
  assert.match(page, /#run-explorer/);
});

test("surface coverage puts four setup cards before methodology detail", () => {
  const page = source("app/surface-coverage/page.tsx");
  assert.ok(page.indexOf("title=\"Surface Control Center\"") < page.indexOf("<EvidenceTruthPanel"));
  assert.equal((page.match(/name=\"Browser\"|name: \"Browser\"/g) || []).length > 0, true);
  for (const method of ["MCP Gateway", "LLM Gateway", "Endpoint Agent"]) assert.match(page, new RegExp(method));
});

test("health and validation copy keeps source limits explicit", () => {
  const monitoring = source("app/monitoring/page.tsx");
  const jobs = source("app/ops/jobs/page.tsx");
  const validation = source("app/validation/coverage/page.tsx");
  assert.match(monitoring, /ingest stubs/);
  assert.match(monitoring, /raw telemetry/i);
  assert.doesNotMatch(jobs, /Celery Beat/);
  assert.match(jobs, /Scheduled background work/i);
  assert.match(validation, /Run a control test/);
  assert.match(validation, /Coverage methodology/);
});

test("GitHub shell uses one app-level content root", () => {
  const page = source("app/control-coverage/source-control/github-repository-boundary/page.tsx");
  assert.equal((page.match(/<main\b/g) || []).length, 0);
});
