import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

test("the shared shell exposes exactly the seven approved primary destinations", () => {
  const navigation = source("lib/navigation.ts");
  const primaryBlock = navigation.slice(
    navigation.indexOf("export const LIFECYCLE_NAV_ITEMS"),
    navigation.indexOf("export const SPECIALIST_WORKSPACES")
  );
  const labels = [...primaryBlock.matchAll(/\n\s+label: "([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(labels, ["Overview", "Inventory", "Activity", "Policies", "Deployments", "Reports", "Integrations"]);
  assert.doesNotMatch(primaryBlock, /label: "Settings"/);
});

test("the overview leads with evidence-backed priority actions before narrative modules", () => {
  const page = source("app/dashboard/command-center/page.tsx");
  assert.ok(page.indexOf("<TopActionsNow actions={priorityActions} />") < page.indexOf("<EvidenceRiver events={governanceOverview.river} live={streamConnected} />"));
  assert.ok(page.indexOf("<EvidenceRiver events={governanceOverview.river} live={streamConnected} />") < page.indexOf("<GovernanceStoryline model={governanceOverview} />"));
  assert.match(page, /title="Overview"/);
  for (const label of ["Browser Extension", "MCP Gateway", "LLM Gateway", "Endpoint Agent"]) assert.match(page, new RegExp(`label: "${label}"`));
  assert.match(page, /Live data unavailable:/);
});

test("inventory and guided demo keep the primary task visible in the first view", () => {
  const inventory = source("components/discovery/discovery-asset-inventory.tsx");
  assert.match(inventory, /title="AI asset inventory"/);
  assert.match(inventory, /No assets match these filters/);
  assert.match(inventory, /<div className="mt-5 overflow-hidden/);

  const demo = source("app/guided-demo/page.tsx");
  assert.match(demo, /title="Guided demo"/);
  assert.match(demo, /Run a real, tenant-scoped walkthrough/);
  assert.match(demo, /Run guided demo/);
});

test("AI IAM keeps unresolved agents and gateway setup reachable", () => {
  const page = source("app/ai-iam/page.tsx");
  assert.match(page, /href="\/interaction-security"/);
  assert.match(page, /Set up LLM Gateway/);
  assert.match(page, /href="\/discovery\/unknown"/);
  assert.match(page, /Review unknown AI/);
});

test("access failures provide a truthful retry path", () => {
  const callback = source("app/login/oidc/callback/page.tsx");
  assert.match(callback, /Sign in could not be completed/);
  assert.match(callback, /href="\/login"/);
  const operationalState = source("components/operational-state.tsx");
  assert.match(operationalState, /still in progress or unavailable/);
});

test("owned summary surfaces keep missing data and technical evidence explicit", () => {
  const executive = source("app/discovery/executive-summary/page.tsx");
  assert.match(executive, /title="Executive summary"/);
  assert.match(executive, /No observed data/);
  assert.match(executive, /Executive summary data unavailable/);
  assert.doesNotMatch(executive, /setFindings\(\[\]\)/);

  const analytics = source("app/analytics/page.tsx");
  assert.match(analytics, /Analytics data unavailable/);
  assert.match(analytics, /No zero values are being substituted/);
  assert.doesNotMatch(analytics, /setFindings\(\[\]\)/);

  const ecosystem = source("components/ecosystem/ai-ecosystem-workspace.tsx");
  assert.match(ecosystem, /Technical details/);
  assert.match(ecosystem, /Technical evidence rules|Evidence rules and source detail/);
  assert.match(ecosystem, />Control surface<\/p>/);
  assert.doesNotMatch(ecosystem, />Deployment surface<\/p>/);
  assert.doesNotMatch(ecosystem, /What you can show right now|No fake green\./);
});

test("source-derived dashboard and footprint values stay withheld during load failures", () => {
  const dashboard = source("app/dashboard/page.tsx");
  assert.match(dashboard, /const hasSourceData = loadState === "ready" \|\| loadState === "stale"/);
  assert.ok(dashboard.indexOf('title="Immediate Action Backlog"') < dashboard.indexOf("{hasSourceData ? <>"));
  assert.match(dashboard, /{hasSourceData \? <>[\s\S]*?<KpiStrip/);
  assert.match(dashboard, /Action backlog will appear when dashboard evidence is available/);
  assert.doesNotMatch(dashboard, /loadState === "loading" \|\| loadState === "unavailable" \? .*KpiStrip/);

  const footprint = source("app/ai-footprint/page.tsx");
  assert.match(footprint, /value: hasSourceData \? graph\.usersCount : "Unknown"/);
  assert.match(footprint, /!hasSourceData \? \([\s\S]*?Alert evidence is unavailable/);
  assert.match(footprint, /No open alerts\./);
});

test("estate inventory and investigation queue lead optional technical detail", () => {
  const estate = source("components/discovery/ai-estate-intelligence.tsx");
  assert.ok(estate.indexOf("Canonical estate") < estate.indexOf("Technical evidence summaries"));
  assert.ok(estate.indexOf("Investigation queue") < estate.indexOf("Coverage and resolution methodology"));
  assert.match(estate, /<summary[^>]*>Technical details<\/summary>/);
  assert.match(estate, /<summary[^>]*>Coverage and resolution methodology<\/summary>/);
});

test("public preview labels sample data before the mock dashboard metrics", () => {
  const home = source("app/page.tsx");
  const note = home.indexOf("Illustrative product preview — sample data, not your workspace.");
  const dashboard = home.indexOf('<section className="min-w-0 bg-[#050b14] p-3 sm:p-4">');
  const firstMetric = home.indexOf("{metrics.map((metric) => (");
  assert.ok(note >= 0, "public preview must identify sample data");
  assert.ok(note < dashboard && note < firstMetric, "sample-data note must precede the mock dashboard and metrics");
  assert.match(home.slice(note - 180, dashboard), /role="note"/);
});
