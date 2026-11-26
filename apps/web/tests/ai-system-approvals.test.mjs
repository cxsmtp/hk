import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

import { mayOpen, settingsNav } from "../src/lib/settings-menu.mjs";

// Settings → AI system approvals: src/lib/ai-system-approvals.ts, the page, the menu entry, and the guide's defaults
// against the API's (app/services/ai_system_approval_service.py).
const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");
const repo = (path) => readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8");

async function loadLib() {
  const result = ts.transpileModule(source("lib/ai-system-approvals.ts"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

const rule = (patch = {}) => ({
  min_approvers: 2,
  allow_self_approval: false,
  approver_roles: ["owner", "admin"],
  allowed_scopes: ["time_bound"],
  default_scope: "time_bound",
  default_duration_hours: 168,
  max_duration_hours: 720,
  ...patch,
});

test("a rule reads in one line, in hours and days as people say them", async () => {
  const { ruleSummary, hoursLabel } = await loadLib();
  assert.equal(hoursLabel(24), "24 hours");
  assert.equal(hoursLabel(168), "7 days");
  assert.equal(hoursLabel(8760), "1 year");
  assert.equal(hoursLabel(1), "1 hour");
  assert.equal(ruleSummary(rule()), "2 approvers, none of them the requester · Time-bound only · time-bound 7 days by default, up to 30 days");
  assert.equal(
    ruleSummary(rule({ min_approvers: 1, allow_self_approval: true, allowed_scopes: ["blanket", "one_time"], default_scope: "blanket" })),
    "1 approver, who may be the requester · Blanket, One-time (default blanket)",
  );
});

test("the form says what the API would refuse, and keeps a rule whole as it changes", async () => {
  const { ruleProblems, withRuleChange, policyPayload, policyChanged, TIER_ORDER } = await loadLib();
  assert.deepEqual(ruleProblems(rule()), []);
  assert.ok(ruleProblems(rule({ allow_self_approval: true })).some((p) => p.includes("only when one approval is needed")));
  assert.ok(ruleProblems(rule({ approver_roles: [] })).some((p) => p.includes("at least one role")));
  assert.ok(ruleProblems(rule({ approver_roles: ["ghost"] }), ["owner", "admin"]).some((p) => p.includes("no role ghost")));
  assert.ok(ruleProblems(rule({ default_duration_hours: 900 })).some((p) => p.includes("no longer than the longest")));
  assert.ok(ruleProblems(rule({ allowed_scopes: ["one_time"], default_scope: "blanket" })).some((p) => p.includes("default scope")));
  // Two approvers turn self-approval off; dropping the default scope moves the default to one still allowed.
  const one = rule({ min_approvers: 1, allow_self_approval: true, allowed_scopes: ["blanket", "time_bound"], default_scope: "blanket" });
  assert.equal(withRuleChange(one, { min_approvers: 2 }).allow_self_approval, false);
  assert.equal(withRuleChange(one, { allowed_scopes: ["time_bound"] }).default_scope, "time_bound");
  assert.deepEqual(withRuleChange(one, { allowed_scopes: ["time_bound", "blanket"] }).allowed_scopes, ["blanket", "time_bound"]);
  const policy = { tiers: Object.fromEntries(TIER_ORDER.map((t) => [t, rule()])), request_ttl_hours: 168 };
  assert.deepEqual(Object.keys(policyPayload(policy).tiers), ["LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED"]);
  assert.equal(policyChanged(policy, policy), false);
  assert.equal(policyChanged(policy, { ...policy, request_ttl_hours: 48 }), true);
});

test("standing approvals and refusals read plainly", async () => {
  const { grantLine, progressLabel, refusalMessage } = await loadLib();
  assert.equal(grantLine({ scope: "blanket", state: "ACTIVE", expires_at: null, origin: "upgrade", lapsed: false }), "Blanket (approved before the workflow; carried over)");
  assert.equal(grantLine({ scope: "one_time", state: "ACTIVE", expires_at: null, origin: "workflow", lapsed: false }), "One-time, not used yet");
  assert.equal(grantLine({ scope: "time_bound", state: "ACTIVE", expires_at: "2026-12-03T14:00:00+00:00", origin: "workflow", lapsed: false }), "Time-bound until 3 Dec 2026, 14:00 UTC");
  assert.equal(grantLine({ scope: "one_time", state: "CONSUMED", expires_at: null, origin: "workflow", lapsed: false }), "One-time, consumed");
  assert.equal(progressLabel({ approvals: [{}], approvals_needed: 2 }), "1 of 2 approvals");
  assert.equal(refusalMessage('{"error":"You asked for this approval."}'), "You asked for this approval.");
  assert.equal(refusalMessage('{"detail":{"code":"approval_required","message":"Ask first."}}'), "Ask first.");
});

test("the page is in the Settings menu under Workflow and calls the approval API", () => {
  assert.ok(existsSync(new URL("../src/app/settings/approvals/page.tsx", import.meta.url)));
  assert.ok(mayOpen("/settings/approvals", ["settings.manage"]) && mayOpen("/settings/approvals", ["discovery.view"]) && !mayOpen("/settings/approvals", ["dashboard.view"]));
  assert.deepEqual(settingsNav(["discovery.view"]).map((g) => g.label), ["People", "Workflow"]);
  const page = source("app/settings/approvals/page.tsx");
  for (const text of ['data-ui="settings-approvals"', 'import "../ftr-settings.css"', "Waiting for a decision", "Standing approvals", "Approval policy by risk tier", "Use the defaults", "/settings/guide/ai-system-approvals"]) assert.ok(page.includes(text), text);
  const api = source("lib/api.ts");
  const router = repo("apps/api/app/api/routers/ai_system_approvals.py");
  for (const path of ["/settings/ai-system-approvals", "/ai-system-approvals/{request_id}/decision", "/ai-system-approvals/grants", "/ai-system-approvals/grants/{grant_id}/revoke"]) assert.ok(router.includes(`"${path}"`), path);
  for (const call of ["/settings/ai-system-approvals", "/ai-system-approvals?status=", "/ai-system-approvals/grants?state=", "/approval-requests"]) assert.ok(api.includes(call), call);
  assert.match(repo("apps/api/app/api/routers/ai_systems.py"), /@router\.post\("\/\{ai_system_id\}\/approval-requests"\)/);
});

test("the guide's defaults are the API's", () => {
  const service = repo("apps/api/app/services/ai_system_approval_service.py");
  const block = service.slice(service.indexOf("DEFAULT_TIER_RULES"), service.indexOf("class ApprovalWorkflowError"));
  const tiers = {};
  for (const m of block.matchAll(/"(LOW|MEDIUM|HIGH|CRITICAL|RESTRICTED)": \{([\s\S]*?)\n    \}/g)) {
    const body = m[2];
    tiers[m[1]] = {
      approvers: Number(/"min_approvers": (\d+)/.exec(body)[1]),
      self: /"allow_self_approval": True/.test(body),
      roles: JSON.parse(/"approver_roles": (\[[^\]]*\])/.exec(body)[1]),
      scopes: JSON.parse(/"allowed_scopes": (\[[^\]]*\])/.exec(body)[1]),
      def: /"default_scope": "(\w+)"/.exec(body)[1],
      hours: Number(/"default_duration_hours": (\d+)/.exec(body)[1]),
      max: Number(/"max_duration_hours": (\d+)/.exec(body)[1]),
    };
  }
  assert.deepEqual(Object.keys(tiers), ["LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED"]);
  const topic = source("lib/guide/topics/approvals.ts");
  const days = (h) => (h === 8760 ? "1 year" : `${h / 24} days`);
  const label = { blanket: "Blanket", one_time: "One-time", time_bound: "Time-bound" };
  const name = { LOW: "Low", MEDIUM: "Medium", HIGH: "High", CRITICAL: "Critical", RESTRICTED: "Restricted" };
  for (const [tier, r] of Object.entries(tiers)) {
    const row = new RegExp(`\\["${name[tier]}", "([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)"\\]`).exec(topic);
    assert.ok(row, tier);
    assert.ok(row[1].startsWith(String(r.approvers)), `${tier} approvers`);
    assert.equal(r.self, false, `${tier}: no self-approval by default`);
    assert.deepEqual(row[2].split(", ").map((s) => s.toLowerCase()), r.roles, `${tier} roles`);
    const scopes = r.scopes.length === 1 ? `${label[r.scopes[0]]} only` : r.scopes.map((s, i) => (i === 0 ? label[s] : label[s].toLowerCase())).join(", ");
    assert.equal(row[3], scopes, `${tier} scopes`);
    assert.ok(row[4].startsWith(label[r.def]), `${tier} default scope`);
    if (r.scopes.includes("time_bound") && r.def === "time_bound") assert.ok(row[4].includes(days(r.hours)) && row[4].includes(days(r.max)), `${tier} hours`);
  }
  // The schedule the guide promises.
  assert.match(repo("apps/api/app/jobs/celery_app.py"), /"ai-system-approval-expiry-every-minute": \{\s*"task": "app\.jobs\.enforcement_jobs\.expire_ai_system_approvals",\s*"schedule": 60\.0/);
  assert.match(service, /DEFAULT_REQUEST_TTL_HOURS = 168/);
  assert.match(topic, /expires after a week/);
});
