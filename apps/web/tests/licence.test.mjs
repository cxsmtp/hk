import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function loadLicence() {
  const result = ts.transpileModule(source("lib/licence.ts"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

test("only the licence gate's 503 with deactivated: true counts as deactivated", async () => {
  const { isDeactivatedAnswer, DEACTIVATED_MESSAGE } = await loadLicence();
  assert.equal(isDeactivatedAnswer(503, { error: DEACTIVATED_MESSAGE, deactivated: true }), true);
  assert.equal(isDeactivatedAnswer(503, { code: "enforcement_fail_closed" }), false);
  assert.equal(isDeactivatedAnswer(503, null), false);
  assert.equal(isDeactivatedAnswer(500, { deactivated: true }), false);
  assert.equal(DEACTIVATED_MESSAGE, "The product has been deactivated. Please reach out to Bhawani Singh.");
});

test("error texts give the API's message", async () => {
  const { errorMessageFrom } = await loadLicence();
  assert.equal(errorMessageFrom('{"error":"This licence expired on 2026-11-01."}'), "This licence expired on 2026-11-01.");
  assert.equal(errorMessageFrom('{"detail":"Insufficient role"}'), "Insufficient role");
  assert.equal(errorMessageFrom(""), "This licence could not be imported.");
  assert.equal(errorMessageFrom("No session"), "No session");
});

test("only a .hawkai file of at most 16 KB is sent", async () => {
  const { licenceFileProblem, MAX_LICENCE_FILE_BYTES, LICENCE_FILE_EXTENSION } = await loadLicence();
  assert.equal(MAX_LICENCE_FILE_BYTES, 16 * 1024);
  assert.equal(LICENCE_FILE_EXTENSION, ".hawkai");
  assert.equal(licenceFileProblem({ name: "Acme-HK-AAAA.hawkai", size: 900 }), "");
  assert.equal(licenceFileProblem({ name: "ACME.HAWKAI", size: 900 }), "");
  assert.equal(licenceFileProblem(null), "Choose a .hawkai licence file.");
  assert.equal(licenceFileProblem({ name: "acme.json", size: 900 }), "Choose a .hawkai licence file: this file does not end in .hawkai.");
  assert.equal(licenceFileProblem({ name: "acme.hawkai", size: 16 * 1024 + 1 }), "This file is too large to be a Hawk AI licence (at most 16 KB).");
  assert.equal(licenceFileProblem({ name: "acme.hawkai", size: 0 }), "This file is empty.");
});

test("the admins' banner shows the trial's time left, and a licence's last 30 days", async () => {
  const { licenceBannerText, timeLeftText } = await loadLicence();
  assert.equal(licenceBannerText(null), "");
  assert.equal(timeLeftText(72, 3), "3 days");
  assert.equal(timeLeftText(53, 3), "2 days 5 hours");
  assert.equal(timeLeftText(5, 1), "5 hours");
  assert.equal(timeLeftText(24, 1), "1 day");
  assert.equal(timeLeftText(undefined, 12), "12 days");
  assert.equal(
    licenceBannerText({ until: "2026-11-28T12:00:00.000Z", daysLeft: 3, hoursLeft: 53, warn: true, trial: true }),
    "Hawk AI trial: 2 days 5 hours left (until 28 Nov 2026, 12:00 UTC). Download the licence request under Settings → Licence, send it to Bhawani Singh, then upload the .hawkai licence you receive.",
  );
  assert.equal(licenceBannerText({ until: "2027-11-01T00:00:00.000Z", daysLeft: 31, hoursLeft: 744, warn: false, trial: false }), "");
  assert.equal(
    licenceBannerText({ until: "2027-11-01T00:00:00.000Z", daysLeft: 30, hoursLeft: 720, warn: true, trial: false }),
    "Hawk AI's licence ends at the end of 31 October 2027 (UTC): 30 days left. Please reach out to Bhawani Singh for a new .hawkai licence, then upload it under Settings → Licence.",
  );
  assert.match(licenceBannerText({ until: "2027-11-01T00:00:00.000Z", daysLeft: 1, hoursLeft: 3, warn: true }), /: 3 hours left\./);
});

test("Settings → Licence says the trial or the licence, the tenants it allows and what was imported", async () => {
  const { productStatusLine, tenantsStatusLine, historyLine, activatedText } = await loadLicence();
  assert.equal(
    productStatusLine({ active: true, trial: true, until: "2026-11-28T12:00:00.000Z", activation: null }),
    "Hawk AI · Trial · Until 28 Nov 2026, 12:00 UTC",
  );
  assert.equal(
    productStatusLine({ active: true, trial: false, until: "2027-08-01T00:00:00.000Z", activation: { org: "Acme Corp", expires: "2027-08-01T00:00:00.000Z" } }),
    "Hawk AI · Licensed · Until the end of 31 Jul 2027 (UTC) · Acme Corp",
  );
  assert.equal(
    productStatusLine({ active: false, trial: false, until: "2026-11-28T12:00:00.000Z", activation: null }),
    "Hawk AI · Deactivated · Until 28 Nov 2026, 12:00 UTC",
  );
  const tenants = { org: "Acme Corp", maxTenants: 3, maxUsers: 25, expires: "2027-11-01T00:00:00.000Z", daysLeft: 300, valid: true, warn: false };
  assert.equal(tenantsStatusLine(tenants), "Several tenants · Unlocked · Acme Corp · Up to 3 tenants · Up to 25 active users in each · Until 1 Nov 2027");
  assert.equal(tenantsStatusLine({ ...tenants, maxUsers: null, maxTenants: 1, valid: false }), "Several tenants · Expired · Acme Corp · Up to 1 tenant · No cap on users · Until 1 Nov 2027");
  assert.equal(
    historyLine({ outcome: "imported", id: "x", org: "Acme Corp", scopes: ["product", "tenants"], expires: "2027-08-01T00:00:00.000Z", at: "2026-11-25T10:00:00.000Z", by: "owner@example.com" }),
    "Licence for Acme Corp (several tenants), until 1 Aug 2027 · imported 25 Nov 2026 by owner@example.com",
  );
  assert.equal(
    historyLine({ outcome: "refused", reason: "This licence expired on 2026-11-01.", at: "2026-11-25T10:00:00.000Z", by: "owner@example.com" }),
    "Refused 25 Nov 2026 by owner@example.com: This licence expired on 2026-11-01.",
  );
  assert.equal(activatedText("2027-08-01T00:00:00.000Z"), "Licensed until 2027-08-01. Opening Hawk AI…");
});

test("the console shows the deactivation page with the installation ID, sign-in and the upload, the banner and Settings → Licence", () => {
  const layout = source("app/layout.tsx");
  assert.match(layout, /<LicenceGate>\s*<AccessGate>\{children\}<\/AccessGate>\s*<\/LicenceGate>/);
  const gate = source("components/licence-gate.tsx");
  assert.match(gate, /The product has been deactivated\./);
  assert.match(gate, /api\s*\.getLicence\(\)/);
  assert.match(gate, /LICENCE_DEACTIVATED_EVENT/);
  assert.match(gate, /<InstallationId id=\{shownId\} \/>/);
  assert.match(gate, /api\.login\(/);
  assert.match(gate, /<LicenceRequestButton /);
  assert.match(gate, /<LicenceUpload/);
  assert.doesNotMatch(gate, /activation code/i);
  const tools = source("components/licence-tools.tsx");
  assert.match(tools, /accept=\{LICENCE_FILE_EXTENSION\}/);
  assert.match(tools, /Upload \.hawkai licence/);
  assert.match(tools, /Download licence request/);
  assert.match(tools, /navigator\.clipboard/);
  assert.match(tools, /document\.execCommand\("copy"\)/);
  const api = source("lib/api.ts");
  assert.match(api, /reportDeactivated\(res\.status, text\)\) throw new Error\(text\)/);
  assert.match(api, /`\$\{API_URL\}\/licence\/import`/);
  assert.match(api, /requestBlob\("\/licence\/request"\)/);
  assert.match(api, /request<LicenceView>\("\/licence\/status"\)/);
  assert.doesNotMatch(api, /licence\/activate|"\/activation"/);
  assert.match(source("components/app-shell.tsx"), /<LicenceBanner \/>/);
  assert.match(source("lib/settings-menu.mjs"), /\{ href: "\/settings\/activation", label: "Licence" \}/);
  const page = source("app/settings/activation/page.tsx");
  assert.match(page, /title="Licence"/);
  assert.match(page, /<InstallationId id=\{view\.installationId\} \/>/);
  assert.match(page, /<LicenceUpload onImported=\{imported\} \/>/);
  assert.match(page, /LICENCE_CHANGED_EVENT/);
});
