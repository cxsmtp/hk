import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const workspaceUrl = new URL("../src/components/ai-iam/identity-governance-workspace.tsx", import.meta.url);
const page = readFileSync(new URL("../src/app/ai-iam/page.tsx", import.meta.url), "utf8");

test("AI IAM exposes the identity-to-policy investigation chain", () => {
  assert.equal(existsSync(workspaceUrl), true);
  const source = readFileSync(workspaceUrl, "utf8");
  for (const label of ["Identities", "Violations", "Policy", "Simulation", "Evidence"]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /<DetailDrawer/);
  assert.match(source, /aria-label="AI identity investigation tabs"/);
});

test("AI IAM makes unknown ownership and missing proof explicit", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  assert.match(source, /Unknown owner/);
  assert.match(source, /No verified evidence/);
  assert.match(source, /evidence_nodes_created/);
  assert.match(source, /policy_version_id/);
  assert.doesNotMatch(source, /owner:\s*["']Hawk/);
});

test("AI IAM reuses real protect, simulation, detail, and evidence routes", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  assert.match(source, /href="\/protect"/);
  assert.match(source, /href="\/simulations"/);
  assert.match(source, /`\/ai-iam\/agents\/\$\{encodeURIComponent/);
  assert.match(source, /`\/auditor\?evidence_id=\$\{encodeURIComponent/);
});

test("AI IAM keeps the advanced control surface behind progressive disclosure", () => {
  assert.match(page, /<IdentityGovernanceWorkspace/);
  assert.match(page, /<details[^>]*id="advanced-ai-iam-tools"/);
  assert.match(page, /Advanced AI IAM tools/);
});

test("AI IAM uses mobile identity cards instead of a page-wide table overflow", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  assert.match(source, /className="divide-y divide-\[#20293a\] md:hidden"/);
  assert.match(source, /className="hidden overflow-x-auto md:block"/);
  assert.match(source, /Inspect identity/);
});

test("AI IAM exposes Akto-clear identities and violations views", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  assert.match(source, /type WorkspaceView = "identities" \| "violations"/);
  assert.match(source, /AI identity workspace views/);
  assert.match(source, />Identities</);
  assert.match(source, />Violations</);
  assert.match(source, /href="\/protect"[^>]*>Policies/);
  assert.match(source, /workspaceView === "violations"/);
  assert.match(source, /inspectViolation/);
});

test("violation view is projected from loaded enforcement events", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  assert.match(source, /const visibleViolations = useMemo/);
  assert.match(source, /allAgentEvents\.filter\(isViolation\)/);
  assert.match(source, /event\.policy_version_id \|\| "Unknown"/);
  assert.match(source, /event\.evidence_nodes_created\?\.length \|\| 0/);
  assert.match(source, /setActiveTab\("violations"\)/);
});

test("violation view uses real trend and decision charts when evidence exists", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  assert.match(source, /AreaChart/);
  assert.match(source, /PieChart/);
  assert.match(source, /const violationTrend = useMemo/);
  assert.match(source, /const decisionBreakdown = useMemo/);
  assert.match(source, /No violation trend is available/);
});

test("AI IAM distinguishes unavailable telemetry from a verified empty tenant", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  assert.match(source, /loadState: OperationalLoadState/);
  assert.match(source, /Identity data is unavailable/);
  assert.match(source, /Violation data is unavailable/);
  assert.match(page, /setPrimaryLoadState/);
  assert.doesNotMatch(page, /load\(\)\.catch\(\(\) => \{\s*setAiSystems\(\[\]\);\s*setAgents\(\[\]\);/);
});
