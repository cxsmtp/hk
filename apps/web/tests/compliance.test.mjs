import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { registerProductionAliases } from "./fixtures/ts-alias-hooks.mjs";
import { mayOpen, settingsNav } from "../src/lib/settings-menu.mjs";

// Settings → Compliance (DESC ISR, UAE IA, CERT-In): the page, its helpers, the sign-in rule fields, the notice on the
// sign-in page, the CEF export and the data location in About.
registerProductionAliases();
const { clockSentence, incidentQuery, retentionDays, STATUS_CHIP, STATUS_LABELS } = await import("../src/lib/compliance.ts");
const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

test("Compliance is under Records for those who may see the audit log", () => {
  assert.ok(mayOpen("/settings/compliance", ["audit.view"]));
  assert.ok(!mayOpen("/settings/compliance", ["dashboard.view"]));
  const records = settingsNav(["audit.view"]).find((g) => g.label === "Records");
  assert.ok(records.items.some((i) => i.href === "/settings/compliance" && i.label === "Compliance"));
});

test("statuses, the clock in words, the report's window and retention", () => {
  assert.deepEqual(Object.keys(STATUS_LABELS).sort(), ["action", "customer", "met", "partial"]);
  assert.equal(STATUS_CHIP.met, "ok");
  assert.equal(clockSentence({ synchronized: true, ntp: { ok: true, offsetSeconds: -0.2, server: "samay1.nic.in" }, problems: [] }), "Synchronised (0.2 s from samay1.nic.in).");
  assert.equal(clockSentence({ synchronized: false, ntp: null, problems: ["Off by 3 s."] }), "Off by 3 s.");
  assert.match(clockSentence({ synchronized: null, ntp: null, problems: [] }), /chrony/);
  assert.equal(incidentQuery("", ""), "");
  assert.equal(incidentQuery("2026-11-25", " 2026-11-26 "), "from=2026-11-25&to=2026-11-26");
  assert.equal(retentionDays("180", 180, 3650), 180);
  assert.equal(retentionDays("179", 180, 3650), null);
  assert.equal(retentionDays("1e3", 180, 3650), null);
});

test("the Compliance page: controls, clock, encryption, settings, the baseline and the incident report", () => {
  const page = source("app/settings/compliance/page.tsx");
  for (const needle of ['data-ui="settings-compliance"', 'data-ui="compliance-controls"', 'data-ui="compliance-settings"', 'data-ui="compliance-baseline"', 'data-ui="compliance-incident-report"', "api.getCompliance()", "api.saveCompliance(", "api.incidentReport(", "signatureFile(", "What the software cannot do"]) {
    assert.ok(page.includes(needle), needle);
  }
  assert.match(page, /passwordRule: \{ minLength: 12, classes: 3, history: 5, maxAgeDays: 90 \}, sessionIdleMinutes: 15/);
  const api = source("lib/api.ts");
  assert.ok(api.includes('request<ComplianceView>("/compliance")'));
  assert.ok(api.includes("/compliance/incident-report"));
  assert.ok(api.includes('format: "csv" | "jsonl" | "cef"'));
});

test("Settings → Sign-in sets the password rule, idle sign-out and notice; the sign-in page shows the notice", () => {
  const signin = source("app/settings/signin/page.tsx");
  for (const name of ["minLength", "classes", "history", "maxAgeDays", "sessionIdleMinutes", "banner"]) assert.ok(signin.includes(`name="${name}"`), name);
  assert.ok(signin.includes('data-ui="signin-password-rule"'));
  const login = source("app/login/page.tsx");
  assert.ok(login.includes('data-ui="sign-in-banner"') && login.includes("options.banner"));
  assert.ok(source("app/settings/audit/page.tsx").includes('exportAs("cef")'));
  assert.ok(source("app/settings/about/page.tsx").includes('data-ui="about-data-location"'));
});
