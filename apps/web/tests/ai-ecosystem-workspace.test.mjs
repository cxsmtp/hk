import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const workspacePath = new URL("../src/components/ecosystem/ai-ecosystem-workspace.tsx", import.meta.url);
const navigationPath = new URL("../src/lib/navigation.ts", import.meta.url);
const userWorkspacePath = new URL("../src/components/users/user-visibility-workspace.tsx", import.meta.url);

test("AI Ecosystem is a first-class bounded visual workspace", () => {
  assert.equal(existsSync(workspacePath), true, "expected the AI Ecosystem workspace to exist");
  const source = readFileSync(workspacePath, "utf8");

  for (const marker of [
    "api.userVisibilityOrganization()",
    "api.userVisibilityDepartments({ page: 1, page_size: 50 })",
    "api.userVisibilityGroups({ page: 1, page_size: 50 })",
    "api.userVisibilityUsers({ page: 1, page_size: 100 })",
    "api.userVisibilityActions({",
    "page_size: 100",
    "api.getDiscoveryEstate()",
    "api.listDiscoveryEcosystems({ page: 1, page_size: 200 })",
    "api.listPolicyPackPlatformInstances()",
    "api.executiveControlCoverage()",
    "api.maturityCurveOverview()",
    "Organization",
    "Departments",
    "Surface coverage",
    "Policies",
    "Attention",
    "Table fallback",
    "Raw prompt content is not included",
    "Current",
    "Partial",
    "Stale",
    "Regressed",
    "Unsupported",
    "Unknown",
    "Open User 360",
    "Open activity lineage",
    "Open Policy Packs",
    "Observed-but-not-canonical actions",
    "Verified/canonical assets",
    "Connect authoritative source",
    "Canonical assets remain separate",
  ]) {
    assert.match(source, new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }

  assert.doesNotMatch(source, /raw_prompt|prompt\.raw|productivity score|employee risk score/i);
  assert.match(source, /aria-label="AI Ecosystem"/);
  assert.match(source, /role="table"/);
});

test("AI Ecosystem is discoverable from the Assets lifecycle", () => {
  const navigation = readFileSync(navigationPath, "utf8");
  assert.match(navigation, /href: "\/ai-ecosystem", label: "Relationship map"/);
});

test("ecosystem User 360 links preserve the existing scoped detail experience", () => {
  const source = readFileSync(userWorkspacePath, "utf8");
  assert.match(source, /useSearchParams/);
  assert.match(source, /searchParams\.get\("user_id"\)/);
  assert.match(source, /void selectUser\(requestedUserId\)/);
});
