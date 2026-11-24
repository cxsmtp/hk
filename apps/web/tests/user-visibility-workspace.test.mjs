import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const workspaceUrl = new URL("../src/components/users/user-visibility-workspace.tsx", import.meta.url);
const pageUrl = new URL("../src/app/users/page.tsx", import.meta.url);
const typesUrl = new URL("../src/lib/types.ts", import.meta.url);
const apiUrl = new URL("../src/lib/api.ts", import.meta.url);
const navigationUrl = new URL("../src/lib/navigation.ts", import.meta.url);

test("Users workspace presents the approved safe visibility and action views", () => {
  assert.equal(existsSync(workspaceUrl), true);
  assert.equal(existsSync(pageUrl), true);
  const source = readFileSync(workspaceUrl, "utf8");
  const page = readFileSync(pageUrl, "utf8");

  for (const label of ["Users", "Departments", "Organization", "Action Explorer", "Groups", "User 360"]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /REDACTED_PREVIEW/);
  assert.match(source, /CONTENT_UNAVAILABLE/);
  assert.match(source, /Unknown evidence/);
  assert.match(source, /Reveal redacted content/);
  assert.match(source, /Policy Packs/);
  assert.match(source, /Current members/);
  assert.match(source, /Membership rules/);
  assert.match(source, /Nested groups/);
  assert.match(source, /Audit history/);
  assert.match(page, /<AppShell>/);
  assert.match(page, /<UserVisibilityWorkspace/);
  assert.doesNotMatch(source, /raw_prompt/);
});

test("User 360 keeps progressive sections source-bound or explicitly unknown", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  for (const label of [
    "Overview",
    "AI usage",
    "AI Accounts & Tenants",
    "Prompts & requests",
    "AI actions",
    "Policies & Policy Packs",
    "Controls & evidence",
    "Activity Lineage",
    "Maturity & trends",
  ]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /Tabs request only the selected safe source projection/);
  assert.match(source, /Unavailable is not treated as covered/);
  for (const label of [
    "Company / enterprise tenant",
    "Partner / external enterprise",
    "Personal",
    "Anonymous",
    "Unknown",
  ]) {
    assert.match(source, new RegExp(label.replace(/[&/]/g, "\\$&")));
  }
  assert.match(source, /id: "accounts"/);
  assert.match(source, /No AI account or provider-tenant evidence is linked/);
});

test("Users workspace uses bounded API routes and keeps full content out of normal types", () => {
  const api = readFileSync(apiUrl, "utf8");
  const types = readFileSync(typesUrl, "utf8");
  const navigation = readFileSync(navigationUrl, "utf8");

  assert.match(api, /userVisibilityUsers/);
  assert.match(api, /userVisibilityActions/);
  assert.match(api, /requestUserVisibilityPromptReveal/);
  assert.match(api, /consumeUserVisibilityPromptReveal/);
  assert.match(types, /UserVisibilityPrompt/);
  assert.match(types, /content_access_level/);
  assert.doesNotMatch(readFileSync(workspaceUrl, "utf8"), /raw_prompt/);
  assert.match(navigation, /href: "\/users"/);
});

test("Users directory and User 360 use the bounded summary, sorting, and lazy-section contracts", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  const api = readFileSync(apiUrl, "utf8");
  const types = readFileSync(typesUrl, "utf8");

  for (const label of [
    "Total known users",
    "Active with AI",
    "Personal AI accounts",
    "Policy coverage needs review",
    "Sort users",
    "Policy stack",
    "Why this policy applies",
  ]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /USER_360_TABS/);
  assert.match(source, /userVisibilityUserExperience/);
  assert.match(source, /userVisibilityPolicyStack/);
  assert.match(api, /userVisibilityDirectorySummary/);
  assert.match(api, /userVisibilityUserExperience/);
  assert.match(api, /userVisibilityPolicyStack/);
  assert.match(types, /UserVisibilityDirectorySummary/);
  assert.match(types, /UserVisibilityPolicyStack/);
});

test("Users workspace offers only a manual, role-gated safe visibility recovery", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  const api = readFileSync(apiUrl, "utf8");
  const types = readFileSync(typesUrl, "utf8");
  const recovery = readFileSync(
    new URL("../src/components/users/user-visibility-recovery.mjs", import.meta.url),
    "utf8",
  );

  assert.match(types, /UserVisibilityAccessGrant/);
  assert.match(api, /createUserVisibilityAccessGrant/);
  assert.match(api, /\/user-visibility\/access-grants/);
  assert.match(source, /getSession/);
  assert.match(source, /visibility_capability_required/);
  assert.match(source, /Enable demo visibility/);
  assert.match(source, /createUserVisibilityAccessGrant/);
  assert.match(source, /loadUserVisibilityData/);
  assert.match(recovery, /reason:\s*reason\.trim\(\)/);
  assert.match(recovery, /view_aggregates/);
  assert.match(recovery, /view_user_metadata/);
  assert.match(recovery, /view_action_details/);
  assert.doesNotMatch(recovery, /capabilities:\s*\[[^\]]*(?:view_evidence|reveal_prompt_content|manage_privacy)/s);
});

test("Action Explorer auto-refreshes while open so live prompt projections are not stale", () => {
  const source = readFileSync(workspaceUrl, "utf8");
  assert.match(source, /ACTION_EXPLORER_REFRESH_MS/);
  assert.match(source, /setInterval\(\(\) => \{\s*void loadActions\(filters\);/s);
  assert.match(source, /clearInterval\(timer\)/);
  assert.match(source, /Prompt: \{preview\}/);
  assert.match(source, /line-clamp-2/);
  assert.match(source, /actionRequestSeq/);
  assert.match(source, /requestSeq !== actionRequestSeq\.current/);
  assert.match(source, /followLatestAction/);
  assert.match(source, /Live-following newest/);
  assert.match(source, /Pinned action/);
  assert.match(source, /setLastActionRefreshAt\(new Date\(\)\.toISOString\(\)\)/);
  assert.match(source, /setFollowLatestAction\(false\)/);
  assert.match(source, /Follow latest/);
});
