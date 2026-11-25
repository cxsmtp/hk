import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function loadUpdates() {
  const result = ts.transpileModule(source("lib/updates-settings.ts"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

const version = (v, tags = [v]) => ({ version: v, label: "", digest: `sha256:${"a".repeat(64)}`, created: "2026-11-25T10:00:00Z", revision: "abc", tags });
const updater = { connected: true, manages: true, heartbeat: null, status: null, pending: null, busy: false };

test("versions are named HK-xx.xx.xx and compared as numbers", async () => {
  const { label, cmpVer } = await loadUpdates();
  assert.equal(label("0.2.0"), "HK-00.02.00");
  assert.equal(label("10.0.7"), "HK-10.00.07");
  assert.equal(cmpVer("0.10.0", "0.9.0"), 1);
  assert.equal(cmpVer("0.1.0", "0.1.0"), 0);
});

test("the newest 3 versions, then 10 more at a time, and the running one always", async () => {
  const { visibleVersions } = await loadUpdates();
  const all = Array.from({ length: 25 }, (_, i) => version(`0.${25 - i}.0`));
  let page = visibleVersions(all, "0.25.0", 3);
  assert.deepEqual(page.rows.map((v) => v.version), ["0.25.0", "0.24.0", "0.23.0"]);
  assert.equal(page.more, 22);
  page = visibleVersions(all, "0.2.0", 3);
  assert.deepEqual(page.rows.map((v) => v.version), ["0.25.0", "0.24.0", "0.23.0", "0.2.0"], "the running one is always listed");
  assert.equal(page.more, 21);
  page = visibleVersions(all, "0.2.0", 13);
  assert.equal(page.rows.length, 14);
  assert.equal(page.more, 11);
  assert.equal(visibleVersions(all, "0.2.0", 33).more, 0);
});

test("each version has its chips and one action: update a newer one, roll back to an older one", async () => {
  const { versionRow, available } = await loadUpdates();
  const u = { running: { version: "0.2.0", label: "HK-00.02.00" }, failed: ["0.4.0"], updater };
  assert.deepEqual(versionRow(version("0.2.0", ["0.2.0", "stable"]), u), { chips: [["ok", "Running"], ["ok", "Stable"]], action: null, why: "" });
  assert.deepEqual(versionRow(version("0.3.0", ["0.3.0", "latest"]), u), { chips: [["", "Latest"]], action: "update", why: "" });
  assert.deepEqual(versionRow(version("0.4.0"), u), { chips: [["bad", "Failed to start"]], action: "update", why: "" }, "by hand it may be tried again");
  assert.equal(versionRow(version("0.1.0"), u).action, "rollback");
  assert.deepEqual(versionRow(version("0.3.0"), { ...u, updater: { ...updater, connected: false } }), { chips: [], action: null, why: "not available" });
  assert.equal(available({ latest: version("0.3.0"), running: u.running, failed: [] }).version, "0.3.0");
  assert.equal(available({ latest: version("0.4.0"), running: u.running, failed: ["0.4.0"] }), null, "a version that failed is not offered as the update");
  assert.equal(available({ latest: version("0.2.0"), running: u.running, failed: [] }), null);
});

test("software integrity's five states, the files that differ, and the notice", async () => {
  const { INTEG, changedFiles, integrityNoticeText } = await loadUpdates();
  assert.deepEqual(INTEG.genuine, ["ok", "Genuine"]);
  assert.deepEqual(INTEG.tampered, ["bad", "Files changed"]);
  assert.deepEqual(INTEG["not-genuine"], ["bad", "Not signed by the release workflow"]);
  assert.deepEqual(INTEG.unconfirmed, ["warn", "Not confirmed yet"]);
  assert.deepEqual(INTEG.unsigned, ["", "Development copy"]);
  const files = { ok: false, checked: 9, changed: ["a.py"], missing: ["b.py"], extra: ["c.py"], counts: { changed: 1, missing: 1, extra: 1 } };
  assert.equal(changedFiles({ state: "tampered", summary: "", files }), "changed a.py · missing b.py · added c.py");
  assert.equal(changedFiles({ state: "genuine", summary: "", files: { ...files, ok: true } }), "");
  assert.equal(integrityNoticeText({ state: "tampered", summary: "1 file differs." }), "Software integrity: Files changed. 1 file differs.");
  assert.equal(integrityNoticeText(null), "");
});

test("events, hours and the updater's callout read as the page words them", async () => {
  const { eventLine, eventBad, EVENTS, HOURS, serverNow, updaterCallout } = await loadUpdates();
  assert.equal(eventLine({ at: "", type: "rolled-back", to: "0.3.0", from: "0.2.0", error: "Hawk AI did not come up within 150 s", automatic: true }), "HK-00.03.00 · from HK-00.02.00 · Hawk AI did not come up within 150 s · by auto-update");
  assert.equal(eventLine({ at: "", type: "restart", action: "restart", by: "owner@example.com" }), "by owner@example.com");
  assert.equal(eventBad("rolled-back") && eventBad("refused") && eventBad("failed"), true);
  assert.equal(eventBad("switch"), false);
  assert.equal(EVENTS.switch, "Switched");
  assert.equal(HOURS.length, 25);
  assert.deepEqual(HOURS[0], { value: "", text: "any time" });
  assert.deepEqual(HOURS[3], { value: "2", text: "02:00" });
  assert.equal(serverNow({ zone: "Asia/Dubai", hour: 2, minute: 5 }), "02:05 (Asia/Dubai)");
  assert.match(updaterCallout({ ...updater, connected: false }), /set HAWK_RELEASE in deploy\/.env/);
  assert.match(updaterCallout({ ...updater, manages: false, heartbeat: { engineError: "api runs hawk-api:local." } }), /cannot update this installation: api runs hawk-api:local\./);
  assert.equal(updaterCallout(updater), "");
});

test("the page is FTR's Updates page: its panels, controls and words", () => {
  const page = source("app/settings/updates/page.tsx");
  for (const text of [
    "✓ Changes save as you type.",
    "Update &amp; recovery",
    "<small>Running</small>",
    "<small>Latest published</small>",
    "<small>Auto-update</small>",
    "This installation follows",
    "Update by itself only in the hour from",
    "Installing by hand is never held back.",
    "Software integrity",
    "Check now",
    "File list SHA-256",
    "Sigstore log entry",
    "Check for updates",
    "Download troubleshooting report",
    "Roll back to this",
    "Update now",
    "Recent events",
    "Nothing yet.",
    "Load {Math.min(10, page.more)} more",
  ]) {
    assert.ok(page.includes(text), text);
  }
  assert.ok(page.includes('import "../ftr-settings.css"'));
  const nav = source("lib/navigation.ts");
  assert.ok(nav.includes('{ href: "/settings/updates", label: "Updates" }'));
  assert.ok(source("components/app-shell.tsx").includes("<IntegrityNotice />"));
});
