import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function loadHandsOff() {
  const result = ts.transpileModule(source("lib/hands-off-settings.ts"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

const problem = { key: "smtp", title: "Email server", detail: "The server rejected that username and password.", tenant: "", outside: false, since: "2026-11-25T10:00:00.000Z", lastAt: "", checks: 2, tried: ["Tried the mail server again after a pause"], notifiedAt: "x", caseId: "" };

test("the self-check's chip is FTR's: All checks pass, a count of problems, or not checked yet", async () => {
  const { healthChip, problemLine } = await loadHandsOff();
  assert.deepEqual(healthChip({ lastCheckAt: "2026-11-25T10:05:00.000Z", everyMinutes: 5, problems: [], events: [], maintainer: "" }), { tone: "ok", label: "All checks pass", text: "Last check: 2026-11-25 10:05 UTC." });
  assert.equal(healthChip({ lastCheckAt: "2026-11-25T10:05:00.000Z", everyMinutes: 5, problems: [problem], events: [], maintainer: "" }).label, "1 problem");
  assert.equal(healthChip({ lastCheckAt: "2026-11-25T10:05:00.000Z", everyMinutes: 5, problems: [problem, problem], events: [], maintainer: "" }).tone, "bad");
  assert.equal(healthChip({ lastCheckAt: "", everyMinutes: 5, problems: [], events: [], maintainer: "" }).label, "Not checked yet");
  assert.equal(healthChip(null).tone, "warn");
  assert.equal(problemLine(problem), "Email server: The server rejected that username and password. Tried: Tried the mail server again after a pause.");
  assert.equal(problemLine({ ...problem, detail: "503", outside: true, tried: [], caseId: "SUP-0002" }), "Email server: 503. The problem is on the far side. Support case SUP-0002.");
});

test("the readiness lines, the days and hours, the payload and the link's token", async () => {
  const { readiness, DAYS, HOURS, handsOffPayload, linkToken } = await loadHandsOff();
  const lines = readiness({ ready: { smtp: true, serverUrl: false }, paused: true, handsOff: { pausedUntil: "2026-12-02T10:00:00.000Z" } });
  assert.deepEqual(lines.map((l) => l.ok), [true, false, false]);
  assert.equal(lines[0].text, "Email server tested");
  assert.match(lines[1].text, /so the email buttons work/);
  assert.equal(lines[2].text, "Paused until 2026-12-02 10:00 UTC");
  assert.deepEqual(DAYS[0], [1, "Monday"]);
  assert.deepEqual(DAYS[6], [0, "Sunday"]);
  assert.equal(HOURS.length, 24);
  assert.deepEqual(HOURS[8], [8, "08:00"]);
  const form = { status: false, statusTo: "a@b.co", statusDay: 1, statusHour: 8, replies: true, imapHost: " imap.b.co ", imapPort: "" };
  assert.deepEqual(handsOffPayload(form, false), { handsOff: { on: false, statusTo: "", statusDay: 1, statusHour: 8, replies: true, imapHost: "imap.b.co", imapPort: 993 } });
  assert.equal(handsOffPayload({ ...form, status: true }).handsOff.statusTo, "a@b.co");
  assert.equal(linkToken("#a=eyJhIjoicGF1c2UifQ.abc_-123"), "eyJhIjoicGF1c2UifQ.abc_-123");
  assert.equal(linkToken("#a=nodot"), "");
  assert.equal(linkToken(""), "");
});

test("Settings → Hands-off keeps MZ's wording in FTR's settings look, at /settings/hands-off", () => {
  const page = source("app/settings/hands-off/page.tsx");
  for (const text of [
    "Hands-off: set it up once, then leave it",
    "What should Hawk AI do on its own?",
    "Email a short status every week",
    "It also checks itself every few minutes, puts right what it can, and tells the administrators.",
    "The weekly status goes to",
    "The weekly status, on",
    "Steer it by email",
    "Each asks once more before it acts.",
    "Also read replies: one word, such as PAUSE, RESUME, RUN, STATUS or STOP",
    "Mailbox server (IMAP), for the email server&apos;s account",
    "It reads only unread mail there, acts only on a reply from the address the email went to, and marks it read.",
    "Turn on hands-off",
    "Send the status now",
    "Turn off hands-off",
    "Turn off hands-off? The weekly status stops and replies are no longer read. The self-check keeps running.",
    "Self-check",
  ]) {
    assert.ok(page.includes(text), text);
  }
  assert.ok(page.includes('import "../ftr-settings.css"'));
  for (const cls of ['className="grid g2"', 'className="panel"', 'className="form"', 'className="f"', 'className="check"']) assert.ok(page.includes(cls), cls);
  const box = source("components/self-check-box.tsx");
  for (const text of ["Check now", "Last events", "chip ${chip.tone}"]) assert.ok(box.includes(text), text);
  assert.match(source("lib/navigation.ts"), /href: "\/settings\/hands-off", label: "Hands-off"/);
});

test("Backups & health shows the self-check in FTR's Health panel", () => {
  const page = source("app/settings/backups/page.tsx");
  assert.ok(page.includes("<SelfCheckBox health={health} onCheck={checkNow} busy={checking} />"));
  assert.ok(page.indexOf("<h2>Health</h2>") < page.indexOf("<SelfCheckBox"));
  assert.ok(page.includes('href="/settings/hands-off"'));
});

test("the Yes, do it page asks before it acts, and needs no sign-in", () => {
  const page = source("app/hands-off/confirm/page.tsx");
  assert.ok(page.includes("describeHandsOffLink") && page.includes("confirmHandsOffLink"));
  assert.ok(page.indexOf("describeHandsOffLink") < page.indexOf("confirmHandsOffLink"));
  assert.ok(page.includes("window.history.replaceState"));
  assert.ok(page.includes("Yes, do it"));
  assert.ok(!page.includes("AppShell"));
  const api = source("lib/api.ts");
  assert.match(api, /describeHandsOffLink: \(token: string\) => request<LinkAnswer>\("\/hands-off\/link", \{ method: "POST", body: JSON.stringify\(\{ token \}\) \}, false\)/);
  assert.match(api, /confirmHandsOffLink: \(token: string\) => request<LinkAnswer>\("\/hands-off\/link\/confirm", \{ method: "POST", body: JSON.stringify\(\{ token \}\) \}, false\)/);
});
