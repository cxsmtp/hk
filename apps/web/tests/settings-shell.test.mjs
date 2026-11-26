import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import { inline, mdBlocks, splitVersions } from "../src/lib/changelog.mjs";
import { isSettingsItemActive, jumpMatches, mayOpen, SETTINGS_ENTRY, SETTINGS_GROUPS, settingsJumpEntries, settingsNav } from "../src/lib/settings-menu.mjs";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");
const ALL = ["dashboard.view", "teams.manage", "users.manage", "roles.manage", "security.sso", "activation.manage", "audit.view", "settings.manage", "security.https", "system.update", "backup.manage", "network.manage", "support.manage"];
const labels = (groups) => groups.map((g) => [g.label, g.items.map((i) => i.label)]);

test("the Settings menu has FTR's groups and items, in FTR's order, with Licensing where FTR has Pricing", () => {
  assert.deepEqual(labels(settingsNav(ALL)), [
    ["People", ["People", "Teams", "Roles & permissions", "Sign-in"]],
    ["Licensing", ["Activation codes"]],
    ["Records", ["Audit log", "Connector API activity"]],
    ["System", ["General", "Branding", "Email (SMTP)", "Single sign-on", "HTTPS", "Updates", "Backups & health", "Hands-off", "Network & proxy", "Get help", "Guide", "About"]],
  ]);
  // Every item is a page.
  for (const group of SETTINGS_GROUPS) for (const item of group.items) assert.ok(existsSync(new URL(`../src/app${item.href}/page.tsx`, import.meta.url)), item.href);
  assert.equal(SETTINGS_ENTRY.href, "/settings/people");
});

test("each person sees only what their role allows; the System group only with a System tab of their own", () => {
  // A Viewer: their people and the teams (FTR: dashboard.view), nothing of the system, not even About (the Guide is
  // theirs through Jump to and Get help).
  assert.deepEqual(labels(settingsNav(["dashboard.view"])), [["People", ["People", "Teams"]]]);
  // An Auditor: the records too.
  assert.deepEqual(labels(settingsNav(["dashboard.view", "audit.view"])), [["People", ["People", "Teams"]], ["Records", ["Audit log", "Connector API activity"]]]);
  // A support desk: Get help, and the Guide and About with it.
  assert.deepEqual(labels(settingsNav(["support.manage"]))[1], ["System", ["Get help", "Guide", "About"]]);
  assert.ok(!mayOpen("/settings/email", ["dashboard.view"]) && mayOpen("/settings/email", ["settings.manage"]) && !mayOpen("/settings/nope", ALL));
  assert.ok(isSettingsItemActive("/settings/people", "/settings/people") && !isSettingsItemActive("/settings/peoples", "/settings/people"));
});

test("Jump to finds Settings pages by their name and by 'settings' and the group's name", () => {
  const entries = settingsJumpEntries(ALL);
  assert.deepEqual(jumpMatches(entries, "settings email").map((e) => e.href), ["/settings/email"]);
  assert.deepEqual(jumpMatches(entries, "records").map((e) => e.title), ["Audit log", "Connector API activity"]);
  assert.equal(jumpMatches(entries, "").length, entries.length);
});

test("the shell shows the Settings menu under /settings and Settings in the main menu; no duplicates in Administration", () => {
  const shell = source("components/app-shell.tsx");
  assert.match(shell, /pathname\.startsWith\("\/settings\/"\)/);
  assert.match(shell, /<SettingsNav \/>/);
  assert.match(shell, /min-\[901px\]:grid-cols-\[164px_minmax\(0,1fr\)\] min-\[1361px\]:grid-cols-\[188px_minmax\(0,1fr\)\]/);
  const nav = source("components/settings-nav.tsx");
  assert.match(nav, /className="set-nav" aria-label="Settings"/);
  assert.match(nav, /className="set-label"/);
  assert.match(nav, /className=\{on \? "on" : undefined\}/);
  assert.match(source("components/sidebar.tsx"), /SETTINGS_ENTRY\.href/);
  assert.match(source("components/mobile-lifecycle-nav.tsx"), /SETTINGS_ENTRY\.href/);
  assert.match(source("components/topbar.tsx"), /<JumpTo \/>/);
  const navigation = source("lib/navigation.ts");
  const admin = navigation.slice(navigation.indexOf('label: "Administration"'), navigation.indexOf("] as const"));
  for (const href of ["/settings/people", "/settings/https", "/settings/backups", "/settings/audit", "/settings/help", "/settings/updates"]) assert.ok(!admin.includes(`"${href}"`), href);
  for (const href of ["/guided-demo", "/settings/two-step", "/help"]) assert.ok(admin.includes(`"${href}"`), href);
  const css = source("app/settings/ftr-settings.css");
  for (const rule of [".ftr-settings .set-nav a.on", ".ftr-settings .set-label", ".ftr-settings .brand-grid", ".ftr-settings .img-prev", ".ftr-settings .about-facts", ".ftr-settings .versions-log details", "@font-face { font-family: \"Plex\""]) assert.ok(css.includes(rule), rule);
  assert.ok(existsSync(new URL("../public/fonts/OFL.txt", import.meta.url)) && existsSync(new URL("../public/fonts/ibm-plex-sans-latin-400-normal.woff2", import.meta.url)));
});

test("General, Branding, Email (SMTP) and About keep FTR's panels, controls and wording", () => {
  const general = source("app/settings/general/page.tsx");
  for (const text of ["Hosts &amp; features <small>The name, logo and look are under Branding</small>", "(set by PUBLIC_URL)", "(set by TRUSTED_HOSTS)", "off by default", "Back to what was saved."]) assert.ok(general.includes(text), text);
  const branding = source("app/settings/branding/page.tsx");
  for (const text of ["App name", "Under the name", "Company name <small>on every report</small>", "up to 200 KB", "up to 100 KB", "Look of the app", "The last saved setting is kept.", "✓ Changes save as you type."]) assert.ok(branding.includes(text), text);
  const email = source("app/settings/email/page.tsx");
  for (const text of ["Email server (SMTP)", "Not tested: nothing is sent until it is", "Implicit TLS", "Check the mail server&apos;s certificate", "The server needs a sign-in", "Kept: type to replace", "Who may reset a forgotten password by email", "Links in emails point at", "Test connection", "Send test email", "Send a test to (you by default)"]) assert.ok(email.includes(text), text);
  const about = source("app/settings/about/page.tsx");
  for (const text of ["about-facts", "On premise, your data stays yours.", "Terms of use &amp; license", "What is new <small>the latest three versions; earlier ones ten at a time</small>", "earlier version", "Versions and updates"]) assert.ok(about.includes(text), text);
  for (const page of [general, branding, email, about]) assert.ok(page.includes('import "../ftr-settings.css"'));
});

test("About reads CHANGELOG.md as FTR does: versions newest first, headings, lists, bold and code", () => {
  const log = "# Hawk AI version log\n\nIntro.\n\n## HK-00.02.00 — pending\n\n- **Updates.** One `click`\n  carries on.\n  - inside\n- second\n\n## HK-00.01.00 — 2026-11-25\n\n- first\n";
  const versions = splitVersions(log);
  assert.deepEqual(versions.map((v) => v.title), ["HK-00.02.00 — pending", "HK-00.01.00 — 2026-11-25"]);
  const blocks = mdBlocks(versions[0].body);
  assert.equal(blocks.length, 1);
  assert.deepEqual(blocks[0].items.map((i) => i.text), ["**Updates.** One `click` carries on.", "second"]);
  assert.deepEqual(blocks[0].items[0].children, [{ text: "inside" }]);
  assert.deepEqual(inline("**Updates.** One `click` <b>"), [{ kind: "b", text: "Updates." }, { kind: "text", text: " One " }, { kind: "code", text: "click" }, { kind: "text", text: " <b>" }]);
});
