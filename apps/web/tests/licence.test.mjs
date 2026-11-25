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
  assert.equal(errorMessageFrom('{"error":"This activation code expired on 2026-11-01."}'), "This activation code expired on 2026-11-01.");
  assert.equal(errorMessageFrom('{"detail":"Insufficient role"}'), "Insufficient role");
  assert.equal(errorMessageFrom(""), "This activation code is not valid.");
  assert.equal(errorMessageFrom("No session"), "No session");
});

test("the admins' banner shows from 30 days before, with the last day and the days left", async () => {
  const { licenceBannerText } = await loadLicence();
  assert.equal(licenceBannerText(null), "");
  assert.equal(licenceBannerText({ until: "2027-02-01T00:00:00.000Z", daysLeft: 31, warn: false }), "");
  assert.equal(
    licenceBannerText({ until: "2027-02-01T00:00:00.000Z", daysLeft: 30, warn: true }),
    "Hawk AI stops working at the end of 31 January 2027 (UTC) unless it is activated: 30 days left. Please reach out to Bhawani Singh for an activation code, then enter it under Settings → Activation codes.",
  );
  assert.match(licenceBannerText({ until: "2027-02-01T00:00:00.000Z", daysLeft: 1, warn: true }), /: 1 day left\./);
});

test("the Activation codes page says until when Hawk AI works and what the tenants code allows", async () => {
  const { productStatusLine, tenantsStatusLine, historyLine, activatedText } = await loadLicence();
  assert.equal(
    productStatusLine({ active: true, until: "2027-02-01T00:00:00.000Z", activation: null }),
    "Hawk AI · Active · Until the end of 31 Jan 2027 (UTC)",
  );
  assert.equal(
    productStatusLine({ active: false, until: "2027-08-01T00:00:00.000Z", activation: { org: "Everyone", expires: "2027-08-01T00:00:00.000Z" } }),
    "Hawk AI · Deactivated · Until the end of 31 Jul 2027 (UTC) · Everyone",
  );
  const tenants = { org: "Acme Corp", maxTenants: 3, maxUsers: 25, expires: "2027-11-01T00:00:00.000Z", daysLeft: 300, valid: true, warn: false };
  assert.equal(tenantsStatusLine(tenants), "Several tenants · Unlocked · Acme Corp · Up to 3 tenants · Up to 25 active users in each · Until 1 Nov 2027");
  assert.equal(tenantsStatusLine({ ...tenants, maxUsers: null, maxTenants: 1, valid: false }), "Several tenants · Expired · Acme Corp · Up to 1 tenant · No cap on users · Until 1 Nov 2027");
  assert.equal(
    historyLine({ id: "x", org: "Everyone", scope: "product", action: "activate", expires: "2027-08-01T00:00:00.000Z", at: "2026-11-25T10:00:00.000Z", by: "deactivation page (10.0.0.1)" }),
    "Product code for Everyone, until 1 Aug 2027 · entered 25 Nov 2026 by deactivation page (10.0.0.1)",
  );
  assert.equal(activatedText("2027-08-01T00:00:00.000Z"), "Activated until 2027-08-01. Opening Hawk AI…");
});

test("the console shows the deactivation page, the banner and Settings → Activation codes", () => {
  const layout = source("app/layout.tsx");
  assert.match(layout, /<LicenceGate>\{children\}<\/LicenceGate>/);
  const gate = source("components/licence-gate.tsx");
  assert.match(gate, /The product has been deactivated\./);
  assert.match(gate, /Enter an activation code/);
  assert.match(gate, /api\s*\.getLicence\(\)/);
  assert.match(gate, /LICENCE_DEACTIVATED_EVENT/);
  const api = source("lib/api.ts");
  assert.match(api, /reportDeactivated\(res\.status, text\)\) throw new Error\(text\)/);
  assert.match(api, /"\/licence\/activate"/);
  assert.match(source("components/app-shell.tsx"), /<LicenceBanner \/>/);
  assert.match(source("lib/navigation.ts"), /\{ href: "\/settings\/activation", label: "Activation codes" \}/);
  const page = source("app/settings/activation/page.tsx");
  assert.match(page, /Apply the code/);
  assert.match(page, /Applied: \$\{result\.applied\}\./);
});
