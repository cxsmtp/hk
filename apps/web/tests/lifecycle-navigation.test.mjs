import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const navigation = readFileSync(new URL("../src/lib/navigation.ts", import.meta.url), "utf8");
const sidebar = readFileSync(new URL("../src/components/sidebar.tsx", import.meta.url), "utf8");
const mobileNavigation = readFileSync(new URL("../src/components/mobile-lifecycle-nav.tsx", import.meta.url), "utf8");
const appShell = readFileSync(new URL("../src/components/app-shell.tsx", import.meta.url), "utf8");
const topbar = readFileSync(new URL("../src/components/topbar.tsx", import.meta.url), "utf8");

test("lifecycle navigation exposes seven customer destinations", () => {
  for (const label of ["Overview", "Inventory", "Activity", "Policies", "Deployments", "Reports", "Integrations"]) {
    assert.match(navigation, new RegExp(`label: [\"']${label}[\"']`));
  }
  assert.match(navigation, /export const LIFECYCLE_NAV_ITEMS/);
  assert.match(navigation, /satisfies readonly/);
  assert.match(sidebar, /LIFECYCLE_NAV_ITEMS/);
  assert.doesNotMatch(sidebar, /const groups: NavGroup/);
});

test("active lifecycle modules own the approved contextual subnavigation", () => {
  assert.match(navigation, /children\?: readonly LifecycleNavigationChild\[\]/);
  for (const label of [
    "Activity",
    "Interaction Security",
    "Runtime Intelligence",
    "Estate overview",
    "Identities & access",
    "Policy Builder",
    "Simulations",
    "Surface Coverage",
    "GitHub",
    "Automated Auditor",
    "Action Traces",
  ]) {
    assert.match(navigation, new RegExp(`label: ["']${label}["']`));
  }
  for (const href of [
    "/interaction-security",
    "/runtime-intelligence/overview",
    "/ai-iam",
    "/discovery/findings",
    "/policies",
    "/simulations",
    "/integrations",
    "/auditor/conflicts",
  ]) {
    assert.match(navigation, new RegExp(`href: ["']${href.replaceAll("/", "\\/")}["']`));
  }
  assert.match(navigation, /isLifecycleItemActive/);
  assert.match(sidebar, /active && !collapsed && item\.children\?\.length/);
  assert.match(sidebar, /aria-label=\{`\$\{item\.label\} workspace navigation`\}/);
});

test("specialist tools keep only infrequent operations and administration", () => {
  assert.match(navigation, /SPECIALIST_WORKSPACES/);
  const specialistStart = navigation.indexOf("export const SPECIALIST_WORKSPACES");
  const specialistEnd = navigation.indexOf("function normalizeRole", specialistStart);
  const specialistBlock = navigation.slice(specialistStart, specialistEnd);
  assert.match(specialistBlock, /ops\/jobs/);
  assert.match(specialistBlock, /guided-demo/);
  assert.doesNotMatch(specialistBlock, /interaction-security|runtime-intelligence|simulations|integrations|ai-iam|surface-coverage/);
});

test("the customer areas remain reachable on mobile", () => {
  assert.match(mobileNavigation, /LIFECYCLE_NAV_ITEMS/);
  assert.match(mobileNavigation, /aria-label=["']Mobile lifecycle navigation["']/);
  assert.match(mobileNavigation, /activeItem\?\.children/);
  assert.match(mobileNavigation, /Mobile contextual navigation/);
  assert.match(appShell, /<MobileLifecycleNav/);
});

test("administration remains available from the signed-in account control", () => {
  assert.match(topbar, /Account and administration/);
  assert.match(topbar, /SPECIALIST_WORKSPACES/);
  assert.match(topbar, /Sign out/);
});
