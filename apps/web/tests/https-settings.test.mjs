import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function loadHttps() {
  const result = ts.transpileModule(source("lib/https-settings.ts"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

const viewing = { secure: false, host: "hawk.acme.io:3000", httpsUrl: "https://hawk.acme.io:3000", httpUrl: "http://hawk.acme.io", httpRedirectPort: 80, httpsPort: 3000 };

test("the modes and HSTS ages are named as FTR's Settings → HTTPS names them", async () => {
  const { MODE_LABELS, MODES, hstsAgeLabel, modeChip } = await loadHttps();
  assert.deepEqual(MODES, ["http", "both", "https"]);
  assert.deepEqual(MODE_LABELS, { http: "HTTP only", both: "HTTP and HTTPS", https: "HTTPS only" });
  assert.deepEqual([86400, 604800, 15768000, 31536000, 42].map(hstsAgeLabel), ["a day", "a week", "half a year", "a year", "42 s"]);
  assert.deepEqual(["https", "both", "http"].map(modeChip), ["ok", "warn", "bad"]);
});

test("the certificate chip: self-signed warns, unusable is bad, none over plain http", async () => {
  const { certificateChip, certificateIssues, sourceLabel } = await loadHttps();
  const summary = { subject: "hawk.acme.io", selfSigned: false };
  assert.equal(certificateChip({ mode: "http", certificate: { summary } }), null);
  assert.deepEqual(certificateChip({ mode: "both", certificate: { source: "self-signed", summary } }), { kind: "warn", text: "Self-signed: browsers warn" });
  assert.deepEqual(certificateChip({ mode: "https", certificate: { source: "uploaded", usable: false, summary } }), { kind: "bad", text: "Not usable" });
  assert.deepEqual(certificateChip({ mode: "https", certificate: { source: "uploaded", usable: true, summary } }), { kind: "ok", text: "Trusted" });
  assert.deepEqual(
    certificateIssues({ checks: [{ level: "ok", title: "Fine" }, { level: "warn", title: "Expires in 9 days", detail: "Ask IT for the renewal now" }, { level: "error", title: "Expired" }] }),
    ["Expires in 9 days: Ask IT for the renewal now", "Expired"],
  );
  assert.equal(sourceLabel({ certificate: { source: "environment" } }), "from the server options");
  assert.equal(sourceLabel({ certificate: null, uploaded: { subject: "x" } }), "uploaded here");
});

test("names, the request form and the Let's Encrypt line", async () => {
  const { splitNames, requestNames, acmeLine, asksToConfirm } = await loadHttps();
  assert.deepEqual(splitNames("hawk.acme.io, www.acme.io  10.0.0.5"), ["hawk.acme.io", "www.acme.io", "10.0.0.5"]);
  assert.equal(requestNames({ selfSignedNames: ["hawk.acme.io"], viewing }), "hawk.acme.io");
  assert.equal(requestNames({ selfSignedNames: [], viewing: { ...viewing, host: "other.acme.io" } }), "other.acme.io");
  const when = () => "25 Nov, 10:00";
  assert.equal(acmeLine({ running: true }, when), "Working on it…");
  assert.equal(acmeLine({ running: false, last: { at: "x", error: "Let's Encrypt: no" } }, when), "Last attempt failed: Let's Encrypt: no");
  assert.equal(acmeLine({ running: false, last: { at: "2026-11-25T10:00:00Z", ok: true } }, when), "Last attempt 25 Nov, 10:00");
  assert.equal(asksToConfirm("This turns HTTPS off for everyone. Confirm to go ahead."), true);
  assert.equal(asksToConfirm("Open this page over HTTPS and switch there."), false);
});

test("the page keeps FTR's panels, controls and wording, at /settings/https", () => {
  const page = source("app/settings/https/page.tsx");
  for (const text of [
    "How the server is reached",
    "Hardening",
    "Lowest TLS version",
    "HSTS for",
    "HSTS: browsers refuse plain http to this name",
    "Only with HTTPS only and a certificate browsers trust.",
    "Include subdomains",
    "Saved as you change it.",
    "Certificate in use",
    "Upload your certificate",
    "PEM (certificate, chain and key, in any files) or one .pfx",
    "Check and put to use",
    "Put the previous one back",
    "No certificate yet? Ask IT with a request (CSR), or use a self-signed one",
    "Make a self-signed one for these names",
    "Free certificate from Let&apos;s Encrypt",
    "For a public name the internet reaches on port 80. Renewed 30 days before it expires.",
    "Checked like a browser would: it works.",
    "that proves HTTPS works from your browser first",
  ]) {
    assert.ok(page.includes(text), text);
  }
  for (const cls of ['className="grid g2"', 'className="panel"', 'className="seg"', 'className="form"', 'className="f"', 'className="check"', "saved-foot", 'className="kv"', "callout warn"]) {
    assert.ok(page.includes(cls), cls);
  }
  assert.match((source("lib/navigation.ts") + source("lib/settings-menu.mjs")), /href: "\/settings\/https", label: "HTTPS"/);
  const css = source("app/settings/ftr-settings.css");
  // Every rule is scoped: the rest of the console keeps its own look.
  for (const line of css.split("\n").filter((l) => /^[^\s/@:}].*\{/.test(l))) assert.match(line, /^\.ftr-settings/, line);
});
