import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function loadRecords() {
  const result = ts.transpileModule(source("lib/records.ts"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

test("audit labels, details and the verdict are FTR's, with every broken entry of the chain", async () => {
  const { auditLabel, auditBase, auditDetails, auditGroups, auditRefused, verifyVerdict, queryString } = await loadRecords();
  assert.equal(auditLabel("auth.sign_in.refused"), "Sign-in refused");
  assert.equal(auditLabel("refused: backup.restore"), "Refused: Backups · restore");
  assert.equal(auditBase("refused: backup.restore"), "backup.restore");
  assert.equal(auditLabel("audit.refusals_not_listed.sign_in"), "Refusals not listed one by one");
  assert.equal(auditLabel("monitoring.connector.pull"), "Connectors · connector · pull");
  assert.deepEqual(auditDetails({ reason: "x", empty: "", none: null, n: 2, o: { a: 1 } }), [["reason", "x"], ["n", "2"], ["o", '{"a":1}']]);
  assert.deepEqual(auditGroups(["settings.network", "auth.sign_in", "audit.verify"]), ["audit", "settings", "auth"]);
  assert.equal(auditRefused({ action: "refused: x.y" }), true);
  assert.equal(auditRefused({ action: "x.y" }), false);
  const ok = verifyVerdict({ ok: true, entries: 3, events: 3, first: null, last: null, problems: [], unchained: 0, brokenAt: null, why: "" }, () => "");
  assert.deepEqual(ok, { ok: true, title: "", text: "Intact: all 3 entries are chained, none changed or removed." });
  const old = verifyVerdict({ ok: true, entries: 3, events: 3, first: null, last: null, problems: [], unchained: 2, brokenAt: null, why: "" }, () => "");
  assert.match(old.text, /2 older entries were written before the chain began/);
  const bad = verifyVerdict(
    { ok: false, entries: 3, events: 3, first: null, last: null, problems: [{ seq: 2, at: "2026-11-25T10:00:00Z", problem: "Contents changed after it was written." }], unchained: 0, brokenAt: 2, why: "Contents changed after it was written" },
    () => "25 Nov",
  );
  assert.deepEqual(bad, { ok: false, title: "The log was changed", text: " at entry 2 (25 Nov): Contents changed after it was written." });
  assert.equal(queryString({ q: "a b", who: "", connector: ["x", "y"] }), "q=a+b&connector=x%2Cy");
});

test("Get help and Network & proxy word things as CxMissionZero does", async () => {
  const { HELP_STATUS, HELP_KIND, sentToast, helpCrumbs, networkAdvice, proxyNow, STEP_NAMES } = await loadRecords();
  assert.deepEqual(Object.values(HELP_STATUS).map(([label]) => label), ["New", "In progress", "Waiting for reply", "Completed", "Declined"]);
  assert.deepEqual(HELP_KIND, { case: "Support case", enhancement: "Enhancement" });
  assert.deepEqual(sentToast({ request: { id: "SUP-0001" }, emailed: { sent: 0, error: "not tested" } }), { text: "SUP-0001 is kept, but the email did not go: not tested", bad: true });
  assert.equal(helpCrumbs({ mode: "email", email: "help@acme.test" }), "emailed to help@acme.test · answered by email");
  assert.deepEqual(STEP_NAMES, { proxy: "Proxy", tunnel: "Connection", certificate: "Certificate", answer: "Service" });
  assert.match(networkAdvice({ step: "tunnel", ok: false, detail: "", status: 407 }), /^The proxy wants a sign-in/);
  assert.match(networkAdvice({ step: "tunnel", ok: false, detail: "", status: 403 }), /^The proxy does not allow this host/);
  assert.match(networkAdvice({ step: "certificate", ok: false, detail: "" }), /Trust and connect/);
  assert.equal(networkAdvice({ step: "proxy", ok: true, detail: "" }), "");
  assert.equal(proxyNow({ proxy: null, changedAt: "", restart: "R" }), "Connecting directly, without a proxy.");
  assert.equal(
    proxyNow({ proxy: { url: "http://p:8080", username: "u", noProxy: "", source: "settings", running: false, hasPassword: true }, changedAt: "x", restart: "docker compose restart" }),
    "Using the proxy http://p:8080, signing in as u. Restart Hawk AI to use it: docker compose restart.",
  );
});

test("the Records pages keep FTR's panels, controls and wording", () => {
  const audit = source("app/settings/audit/page.tsx");
  for (const text of ["Audit log", "Check the log is intact", "Export CSV", "Search everything", "Every action", "Older entries", "No events", "Nothing matches these filters.", "<th>When</th>", "<th>Address</th>", 'className="audit"']) {
    assert.ok(audit.includes(text), `audit page: ${text}`);
  }
  const activity = source("app/settings/connector-activity/page.tsx");
  for (const text of ["Connector API activity", "API calls · 30 days", "ms on average", "Older entries", "No activity yet", 'className="kpis"', "mpick"]) {
    assert.ok(activity.includes(text), `connector activity page: ${text}`);
  }
  const help = source("app/help/page.tsx");
  for (const text of ["Get help", "Something is not working", "I would like something added or changed", "In a few words", "The details", "How urgent", "Urgent: I cannot work", "Sent by everyone", "What you sent", "Requests you send are listed here.", "help-thread", "Update status", "Status history"]) {
    assert.ok(help.includes(text), `help page: ${text}`);
  }
  const helpSettings = source("app/settings/help/page.tsx");
  for (const text of ["✓ Changes save as you type.", "Send requests to", "Support portal in Hawk AI", "All changes are saved."]) {
    assert.ok(helpSettings.includes(text), `help settings: ${text}`);
  }
  const network = source("app/settings/network/page.tsx");
  for (const text of ["Network &amp; proxy", "Proxy server", "User name, if the proxy asks for one", "Hosts that skip the proxy (comma-separated)", "Check the connection", "Stop using the proxy", "What your network team needs to allow", "Copy for your network team", "Download (.txt)", "Trusted certificates", "Trust and connect", "Upload a certificate…"]) {
    assert.ok(network.includes(text), `network page: ${text}`);
  }
  for (const page of [audit, activity, help, helpSettings, network]) assert.ok(page.includes("ftr-settings.css"));
});

test("the pages are in the Administration menu", () => {
  const nav = source("lib/navigation.ts");
  for (const href of ["/settings/audit", "/settings/connector-activity", "/settings/network", "/settings/help", "/help"]) assert.ok(nav.includes(`href: "${href}"`), href);
});
