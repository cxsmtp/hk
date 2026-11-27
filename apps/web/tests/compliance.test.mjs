import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import { registerProductionAliases } from "./fixtures/ts-alias-hooks.mjs";
import { mayOpen, settingsNav } from "../src/lib/settings-menu.mjs";

// Settings → Compliance (DESC ISR, UAE IA, CERT-In): the page, its helpers, the sign-in rule fields, the notice on the
// sign-in page, the CEF export and the data location in About.
registerProductionAliases();
const { clockSentence, incidentQuery, retentionDays, STATUS_CHIP, STATUS_LABELS, filterRequirements, fixFor, packLine, evidenceQuery, REQUIREMENT_LABELS, REQUIREMENT_CHIP, STATUS_FILTERS, APPLICABILITY_LABELS } = await import("../src/lib/compliance.ts");
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

// Framework packs (apps/api/app/services/compliance_packs): the helpers, the page's tab and component, the API calls,
// and that every pack file's requirements name controls the API's registry has.
const control = (id, status, extra = {}) => ({ id, title: id, status, reason: "", scope: "administrator", href: "/settings/signin", label: "Settings → Sign-in", planned: false, ...extra });
const req = (id, status, applicability, controls = []) => ({ id, title: id, status, applicability, why: "", note: "", controls, evidence: [], attestation: null });

test("pack helpers: labels, filters (gaps first), the next step and the evidence window", () => {
  assert.deepEqual(Object.keys(REQUIREMENT_LABELS).sort(), ["attested", "gap", "met", "not_applicable", "partly", "yours"]);
  assert.equal(REQUIREMENT_CHIP.gap, "bad");
  assert.deepEqual(Object.keys(APPLICABILITY_LABELS), ["product", "customer", "organisational"]);
  assert.deepEqual(STATUS_FILTERS.map((f) => f.key), ["all", "met", "partly", "gap", "yours"]);
  const items = [req("A", "met", "product"), req("B", "gap", "customer"), req("C", "yours", "organisational"), req("D", "partly", "product"), req("E", "attested", "organisational")];
  assert.deepEqual(filterRequirements(items, "all", "all").map((r) => r.id), ["B", "D", "C", "E", "A"]);
  assert.deepEqual(filterRequirements(items, "product", "all").map((r) => r.id), ["D", "A"]);
  assert.deepEqual(filterRequirements(items, "all", "met").map((r) => r.id), ["E", "A"]);
  assert.deepEqual(filterRequirements(items, "all", "gap").map((r) => r.id), ["B"]);
  assert.deepEqual(filterRequirements(items, "organisational", "yours").map((r) => r.id), ["C"]);
  assert.equal(fixFor(req("X", "partly", "product", [control("a", "met"), control("gap.x", "not_configured", { planned: true }), control("b", "partly", { href: "/settings/https" })])).href, "/settings/https");
  assert.equal(fixFor(req("Y", "met", "product", [control("a", "met")])), null);
  const counts = { total: 10, met: 3, attested: 1, not_applicable: 1, partly: 2, gap: 2, yours: 1 };
  assert.equal(packLine(counts), "5 of 10 met or recorded · 2 partly · 2 gaps · 1 yours to record");
  assert.equal(evidenceQuery("2026-10-01", ""), "from=2026-10-01");
});

test("the Compliance page opens on the framework packs, keeps the DESC view, and the packs component does what it says", () => {
  const page = source("app/settings/compliance/page.tsx");
  for (const needle of ['data-ui="compliance-tabs"', "<FrameworkPacks />", "do not by themselves make you compliant or certified"]) assert.ok(page.includes(needle), needle);
  const packs = source("components/compliance/framework-packs.tsx");
  for (const needle of ['data-ui="compliance-packs"', 'data-ui="pack-picker"', 'data-ui="packs-disclaimer"', 'data-ui="pack-filter-who"', 'data-ui="pack-filter-status"', 'data-ui="pack-requirements"', 'data-ui="pack-fix"', 'data-ui="pack-record"', 'data-ui="pack-evidence"', "Download signed evidence", ".getCompliancePacks()", ".getCompliancePack(current)", "api.packEvidence(", "api.recordRequirement(", "api.removeRequirementRecord(", "tools/verify_evidence.py"]) {
    assert.ok(packs.includes(needle), needle);
  }
  const api = source("lib/api.ts");
  for (const needle of ['request<PacksOverview>("/compliance/packs")', "/compliance/packs/${encodeURIComponent(id)}/evidence", "/record`"]) assert.ok(api.includes(needle), needle);
});

test("every pack file maps only to controls the API's registry has, and every control links to a page that exists", () => {
  const dir = new URL("../../api/app/services/compliance_packs/packs/", import.meta.url);
  const registry = readFileSync(new URL("../../api/app/services/compliance_packs/controls.py", import.meta.url), "utf8");
  const ids = new Set([...registry.matchAll(/^\s+Control\("([a-z_.]+)"/gm)].map((m) => m[1]));
  assert.ok(ids.size > 30, `only ${ids.size} controls found`);
  const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  assert.ok(files.length >= 18);
  for (const file of files) {
    const pack = JSON.parse(readFileSync(new URL(file, dir), "utf8"));
    assert.equal(`${pack.id}.json`, file);
    for (const r of pack.requirements) {
      for (const ref of r.controls) assert.ok(ids.has(ref.split(":")[0]), `${file} ${r.id}: ${ref}`);
      if (!r.controls.length) assert.notEqual(r.applicability, "product", `${file} ${r.id}`);
    }
  }
  const hrefs = [...registry.matchAll(/^\s+Control\("[a-z_.]+", "[^"]*", "[^"]*", "[a-z]+", "(\/settings\/[a-z-]+)"/gm)].map((m) => m[1]);
  assert.ok(hrefs.length > 30, `only ${hrefs.length} links found`);
  for (const href of hrefs) assert.ok(existsSync(new URL(`../src/app${href}/page.tsx`, import.meta.url)), href);
});

// Requests from data subjects (apps/api/app/services/data_subject_requests.py): the helpers, the tab, the component and
// the API calls; who may open the page for it.
const { dataRequestQuery, dueWords, nextStatuses, eventWords, DSR_FILTERS, DSR_KIND_LABELS, DSR_STATUS_LABELS } = await import("../src/lib/compliance.ts");

test("data request helpers: filters, due dates in words, the next statuses and the trail", () => {
  assert.deepEqual(DSR_FILTERS.map((f) => f.key), ["open", "overdue", "all", "completed", "refused"]);
  assert.equal(dataRequestQuery("open"), "status=open");
  assert.equal(dataRequestQuery("overdue"), "overdue=true");
  assert.equal(dataRequestQuery("all"), "");
  assert.deepEqual(Object.keys(DSR_KIND_LABELS), ["access", "correction", "erasure", "grievance", "nomination"]);
  assert.deepEqual(Object.keys(DSR_STATUS_LABELS), ["received", "verifying", "in_progress", "completed", "refused"]);
  const base = { status: "received", dueAt: "2026-12-20T00:00:00Z", overdue: false, dueSoon: false, daysLeft: 23 };
  assert.deepEqual(dueWords(base), { text: "Due in 23 days (2026-12-20)", chip: "" });
  assert.deepEqual(dueWords({ ...base, daysLeft: 1, dueSoon: true }), { text: "Due in 1 day (2026-12-20)", chip: "warn" });
  assert.deepEqual(dueWords({ ...base, daysLeft: -3, overdue: true }), { text: "Overdue by 3 days (due 2026-12-20)", chip: "bad" });
  assert.deepEqual(dueWords({ ...base, status: "completed", daysLeft: null }), { text: "Due 2026-12-20", chip: "" });
  assert.deepEqual(nextStatuses("received"), ["verifying", "in_progress", "completed", "refused"]);
  assert.deepEqual(nextStatuses("in_progress"), ["verifying", "completed", "refused"]);
  assert.deepEqual(nextStatuses("completed"), []);
  assert.equal(eventWords({ kind: "status", from: "received", to: "refused" }), "Received → Refused");
  assert.equal(eventWords({ kind: "erased", from: "", to: "completed" }), "Erased by pseudonymisation");
});

test("the Data requests tab: list, record, detail with its trail, export, erasure and settings", () => {
  assert.ok(mayOpen("/settings/compliance", ["compliance.dsr.manage"]));
  const page = source("app/settings/compliance/page.tsx");
  for (const needle of ["<DataRequests />", 'data-ui="compliance-tab-requests"', 'data-ui="compliance-dsr-due"', 'get("tab")']) assert.ok(page.includes(needle), needle);
  const component = source("components/compliance/data-requests.tsx");
  for (const needle of ['data-ui="compliance-data-requests"', 'data-ui="dsr-table"', 'data-ui="dsr-filter"', 'data-ui="dsr-new"', 'data-ui="dsr-detail"', 'data-ui="dsr-timeline"', 'data-ui="dsr-export"', 'data-ui="dsr-erase"', 'data-ui="dsr-settings"', ".listDataRequests(", "api.createDataRequest(", "api.getDataRequest(", "api.updateDataRequest(", "api.exportDataRequest(", "api.eraseDataRequest(", "api.saveDataRequestSettings(", "window.confirm(", "signatureFile("]) {
    assert.ok(component.includes(needle), needle);
  }
  // Tables become cards on a phone through the shared responsive tables: no table of its own layout.
  assert.ok(component.includes('<div className="tw mt">') && !component.includes("data-table="));
  const api = source("lib/api.ts");
  for (const needle of ["/compliance/data-requests", "/compliance/data-requests/settings", "/erase`", "/export`", 'method: "PATCH"']) assert.ok(api.includes(needle), needle);
  const guide = source("lib/guide/topics/compliance.ts");
  assert.ok(guide.includes('id: "data-requests"') && guide.includes("pseudonymisation"));
});
