import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

import { QR_MAX_BYTES, qrMatrix, qrSvgPath } from "../src/lib/qr.mjs";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function load(path) {
  const result = ts.transpileModule(source(path), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

// --- The QR code: CxMissionZero's test/mfa.test.js, against the same independent encoder's matrices ---------------------

const reference = JSON.parse(readFileSync(new URL("./fixtures/qr-reference.json", import.meta.url), "utf8"));
const hexRows = (modules) =>
  modules.map((row) => {
    const bits = row.map((dark) => (dark ? "1" : "0")).join("");
    const padded = bits + "0".repeat((4 - (bits.length % 4)) % 4);
    return padded.match(/.{4}/g).map((nibble) => parseInt(nibble, 2).toString(16)).join("");
  });

test("the QR code is, square for square, what an independent encoder makes: every version from 1 to 20", () => {
  const versions = new Set();
  let compared = 0;
  for (const code of reference.codes) {
    for (const [mask, rows] of Object.entries(code.masks)) {
      const made = qrMatrix(code.text, { mask: Number(mask) });
      assert.equal(made.version, code.version);
      assert.equal(made.size, code.size);
      assert.deepEqual(hexRows(made.modules), rows, `version ${code.version}, mask ${mask}`);
      compared += 1;
    }
    versions.add(code.version);
  }
  assert.deepEqual([...versions].sort((a, b) => a - b), Array.from({ length: 20 }, (_, i) => i + 1));
  assert.ok(compared >= 40);
});

test("the QR picture has the quiet border, and a long authenticator address still fits", () => {
  const uri = "otpauth://totp/Hawk%20AI:ada%40acme.io?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Hawk%20AI&algorithm=SHA1&digits=6&period=30";
  const made = qrMatrix(uri);
  const { side, viewBox, d } = qrSvgPath(uri);
  assert.equal(side, made.size + 8);
  assert.equal(viewBox, `0 0 ${side} ${side}`);
  assert.match(d, /^(M\d+ \d+h\d+v1h-\d+z)+$/);
  assert.throws(() => qrMatrix("x".repeat(QR_MAX_BYTES + 1)), RangeError);
  assert.ok(qrMatrix(uri.replace("ada", "a".repeat(240))).version <= 20);
});

test("the QR code is made in the page: no library, no network", () => {
  const component = source("components/two-step-key.tsx");
  assert.match(component, /from "@\/lib\/qr"/);
  assert.doesNotMatch(component, /https?:\/\//);
  assert.doesNotMatch(source("lib/qr.mjs"), /fetch\(|https?:\/\/(?!www\.w3)/);
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.ok(!Object.keys(pkg.dependencies).some((name) => /qr/i.test(name)));
});

// --- Sign-in helpers ----------------------------------------------------------------------------------------------------

test("the emailed link's token is read from the fragment only", async () => {
  const { resetLinkToken } = await load("lib/sign-in.ts");
  const token = "A".repeat(43);
  assert.equal(resetLinkToken(`#reset=${token}`), token);
  assert.equal(resetLinkToken(`#reset=${token}x`), "");
  assert.equal(resetLinkToken("#reset=short"), "");
  assert.equal(resetLinkToken(""), "");
  const page = source("app/login/reset/page.tsx");
  assert.match(page, /resetLinkToken\(window\.location\.hash\)/);
  assert.match(page, /window\.history\.replaceState/);
});

test("refusals keep the API's sentence and whether to start again", async () => {
  const { refusalFrom, isTwoStepChallenge, ssoRefusal, twoStepHint, domainList, idleHours } = await load("lib/sign-in.ts");
  assert.deepEqual(refusalFrom('{"detail":"Too many failed attempts: try again after 10:15:00 UTC, or ask an administrator."}'), {
    message: "Too many failed attempts: try again after 10:15:00 UTC, or ask an administrator.",
    restart: false,
    sso: false,
  });
  assert.equal(refusalFrom('{"detail":"That sign-in is over","restart":true}').restart, true);
  assert.equal(refusalFrom('{"detail":"Use single sign-on.","sso":true}').sso, true);
  assert.equal(refusalFrom("<html>", "Login failed").message, "Login failed");
  assert.equal(isTwoStepChallenge({ two_step: true, ticket: "t", minutes: 5 }), true);
  assert.equal(isTwoStepChallenge({ access_token: "a" }), false);
  assert.equal(ssoRefusal("#sso=expired"), "That sign-in took too long, or was started in another browser. Try again.");
  assert.equal(ssoRefusal("#sso=nonsense"), "The identity provider's answer could not be verified, so nobody was signed in. Ask an administrator.");
  assert.equal(ssoRefusal("#ticket=abc"), "");
  assert.equal(twoStepHint({ setup: false, recovery: true }), "Enter one of the recovery codes you saved when you turned two-step sign-in on. Each works once.");
  assert.deepEqual(domainList(" @Acme.com, b.io;c.org "), ["acme.com", "b.io", "c.org"]);
  assert.equal(idleHours(480), "8");
});

test("the sign-in page shows the lock and limits, the two-step code, and Forgot your password?", () => {
  const login = source("app/login/page.tsx");
  assert.match(login, /isTwoStepChallenge\(result\)/);
  assert.match(login, /api\.twoStep\(challenge\.ticket/);
  assert.match(login, /Use a recovery code/);
  assert.match(login, /Forgot your password\?/);
  assert.match(login, /api\.askPasswordReset/);
  assert.match(login, /refusalFrom\(err instanceof Error \? err\.message : "", "Login failed"\)/);
  assert.match(login, /ssoRefusal\(window\.location\.hash\)/);
  assert.match(login, /<TwoStepKey setup=\{challenge\.setup\} \/>/);
});

test("Settings pages follow FTR's look: autosave, the saved banner and foot, panels and labels", () => {
  for (const page of ["app/settings/signin/page.tsx", "app/settings/sso/page.tsx"]) {
    const text = source(page);
    assert.match(text, /import "@\/styles\/ftr\.css";/);
    assert.match(text, /autosave\(/);
    assert.match(text, /className="saved-banner"/);
    assert.match(text, /className="saved-foot"/);
    assert.match(text, /className="panel/);
    assert.match(text, /className="f"/);
  }
  const signin = source("app/settings/signin/page.tsx");
  assert.match(signin, /<h2>Forgotten passwords<\/h2>/);
  assert.match(signin, /<h2>How people sign in<\/h2>/);
  assert.match(signin, /Require two-step sign-in for everyone who signs in with a password/);
  const sso = source("app/settings/sso/page.tsx");
  assert.match(sso, /This service, for the identity provider/);
  assert.match(sso, /Add people on their first sign-in/);
  assert.match(sso, /Who may still sign in with a password/);
  const css = source("styles/ftr.css");
  for (const cls of [".panel h2 small", ".saved-banner", ".saved-foot", "label.f", ".callout.warn", ".kv dt", ".chip.ok"]) assert.ok(css.includes(cls), cls);
  const nav = (source("lib/navigation.ts") + source("lib/settings-menu.mjs"));
  assert.match(nav, /\{ href: "\/settings\/signin", label: "Sign-in" \}/);
  assert.match(nav, /\{ href: "\/settings\/sso", label: "Single sign-on" \}/);
  assert.match(nav, /\{ href: "\/settings\/two-step", label: "Two-step sign-in" \}/);
});
