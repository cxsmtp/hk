import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function load(path) {
  const result = ts.transpileModule(source(path), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

test("the API's 403 codes become the change-password and terms pages", async () => {
  const { accessNeededFrom, accessNeededFor } = await load("lib/access.ts");
  assert.equal(accessNeededFrom(403, '{"error":"Choose a new password before continuing.","code":"password_change_required","mustChangePassword":true}'), "password");
  assert.equal(accessNeededFrom(403, '{"error":"Accept the terms of use to continue.","code":"terms_required","termsRequired":true}'), "terms");
  assert.equal(accessNeededFrom(403, '{"detail":"Insufficient role"}'), null);
  assert.equal(accessNeededFrom(401, '{"code":"terms_required"}'), null);
  assert.equal(accessNeededFrom(403, "not json"), null);

  const terms = { version: "1.0", organisationAccepted: true, accepted: true, canAcceptForOrganisation: true };
  assert.equal(accessNeededFor({ must_change_password: true, terms: { ...terms, accepted: false } }), "password");
  assert.equal(accessNeededFor({ must_change_password: false, terms: { ...terms, accepted: false } }), "terms");
  assert.equal(accessNeededFor({ must_change_password: false, terms }), null);
  assert.equal(accessNeededFor(null), null);
});

test("the password rule matches the API's, and the change page checks the two new passwords", async () => {
  const { passwordProblem, newPasswordProblem } = await load("lib/access.ts");
  assert.equal(passwordProblem("short"), "Use at least 12 characters.");
  assert.equal(passwordProblem("aaaaaaaaaaaaaa"), "That password is too repetitive.");
  assert.equal(passwordProblem("x".repeat(60) + "abcdefghijklm"), "That password is too long.");
  assert.equal(passwordProblem("a-new-Password-2026"), "");
  assert.equal(newPasswordProblem("", "a-new-Password-2026", "a-new-Password-2026"), "Enter your current password.");
  assert.equal(newPasswordProblem("Hq7Tz-mWb3K-p9XcR-a4NfE", "a-new-Password-2026", "a-new-Password-2027"), "The two new passwords are not the same.");
  assert.equal(newPasswordProblem("a-new-Password-2026", "a-new-Password-2026", "a-new-Password-2026"), "Choose a password different from the current one.");
  assert.equal(newPasswordProblem("Hq7Tz-mWb3K-p9XcR-a4NfE", "a-new-Password-2026", "a-new-Password-2026"), "");
});

test("every owner or admin accepts the licence agreement for the organisation; others wait, then accept the terms of use", async () => {
  const { termsStep } = await load("lib/access.ts");
  assert.equal(termsStep({ organisationAccepted: false, canAcceptForOrganisation: true }), "organisation");
  assert.equal(termsStep({ organisationAccepted: true, canAcceptForOrganisation: true }), "organisation");
  assert.equal(termsStep({ organisationAccepted: false, canAcceptForOrganisation: false }), "wait");
  assert.equal(termsStep({ organisationAccepted: true, canAcceptForOrganisation: false }), "person");
});

test("the administrator's acceptance needs read, company, full name, email and authorised", async () => {
  const { termsFormProblem } = await load("lib/access.ts");
  const ok = { read: true, companyName: "Acme LLC", fullName: "Ada Admin", email: "ada@acme.example", authorised: true };
  assert.equal(termsFormProblem(ok), "");
  assert.match(termsFormProblem({ ...ok, read: false }), /Read the agreement/);
  assert.match(termsFormProblem({ ...ok, companyName: " " }), /company/);
  assert.match(termsFormProblem({ ...ok, fullName: "A" }), /full name/);
  assert.match(termsFormProblem({ ...ok, email: "ada" }), /email address/);
  assert.match(termsFormProblem({ ...ok, authorised: false }), /authorised/);
});

test("the emailed copy's status reads plainly", async () => {
  const { termsCopyStatus } = await load("lib/access.ts");
  const base = { to: "ada@acme.example", sentAt: null, attempts: 0, lastError: "", nextAttemptAt: null };
  const when = (iso) => iso.slice(0, 10);
  assert.equal(termsCopyStatus({ ...base, state: "sent", sentAt: "2026-12-01T10:00:00Z" }, when), "Copy emailed to ada@acme.example on 2026-12-01.");
  assert.match(termsCopyStatus({ ...base, state: "waiting" }, when), /^Will be emailed to ada@acme\.example when the mail server is set up/);
  assert.match(termsCopyStatus({ ...base, state: "failed", attempts: 10, lastError: "down" }, when), /failed after 10 tries \(down\)/);
});

test("the terms render as escaped HTML without the top heading", async () => {
  const { termsHtml } = await load("lib/access.ts");
  const html = termsHtml("# Title\n\nVersion 1.0\n\n## 1. What\n\nUse **the software** with `LICENSE` <script>.\n\n- one\n  - nested\n- two\n");
  assert.equal(
    html,
    "<p>Version 1.0</p><h3>1. What</h3><p>Use <strong>the software</strong> with <code>LICENSE</code> &lt;script&gt;.</p><ul><li>one<ul><li>nested</li></ul></li><li>two</li></ul>",
  );
  const terms = readFileSync(new URL("../../../TERMS.md", import.meta.url), "utf8");
  assert.match(terms, /^Version 2\.0 /m);
  assert.match(terms, /\{\{LICENSOR_LEGAL_NAME\}\}/);
  assert.match(termsHtml(terms), /<h3>11\. Limitation of liability<\/h3>/);
  assert.match(termsHtml(terms), /<h3>Schedule 2 — Terms of use for users and acceptable use<\/h3>/);
});

test("the version is shown like CxMissionZero's, from the one VERSION file", async () => {
  const { displayVersion, cleanSetupCode } = await load("lib/access.ts");
  assert.equal(displayVersion("1.2.3"), "HK-01.02.03");
  assert.equal(displayVersion("0.1"), "HK-00.01.00");
  assert.equal(displayVersion("10.0.7-beta"), "HK-10.00.07");
  assert.equal(displayVersion(""), "HK-00.00.00");
  assert.equal(cleanSetupCode(" abcd-efgh-jklm "), "ABCD-EFGH-JKLM");

  const config = readFileSync(new URL("../next.config.mjs", import.meta.url), "utf8");
  assert.match(config, /\.\.\/\.\.\/VERSION/);
  assert.match(config, /NEXT_PUBLIC_HAWK_VERSION/);
  assert.match(readFileSync(new URL("../../../VERSION", import.meta.url), "utf8"), /^\d+\.\d+\.\d+\n$/);
});

test("every screen has the gates and the version, and the API client reports the 403 codes", () => {
  const layout = source("app/layout.tsx");
  assert.match(layout, /<LicenceGate>\s*<AccessGate>\{children\}<\/AccessGate>\s*<\/LicenceGate>/);
  assert.match(layout, /<VersionTag \/>/);
  const api = source("lib/api.ts");
  assert.match(api, /reportAccessNeeded\(res\.status, text\)/);
  assert.match(api, /"\/auth\/me\/password"/);
  assert.match(api, /"\/terms\/accept"/);
  assert.match(api, /"\/setup"/);
  const gate = source("components/access-gate.tsx");
  assert.match(gate, /Choose a new password/);
  assert.match(gate, /Accept and continue/);
  for (const id of ["terms-read", "terms-company", "terms-name", "terms-email", "terms-authorised"]) assert.match(gate, new RegExp(`id="${id}"`));
  assert.match(api, /"\/terms\/acceptances"/);
  assert.match(gate, /Decline and sign out/);
  assert.match(source("app/login/page.tsx"), /Create the first administrator/);
  assert.match(source("lib/api-url.ts"), /A path on the console's own address/);
});
