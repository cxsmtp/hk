import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";


const page = readFileSync(
  "src/app/runtime-intelligence/transactions/[id]/page.tsx",
  "utf8",
);
const api = readFileSync("src/lib/api.ts", "utf8");
const types = readFileSync("src/lib/types.ts", "utf8");
const actionTrace = readFileSync(
  "src/app/runtime-intelligence/action-trace/[id]/page.tsx",
  "utf8",
);


test("banking transaction view uses the evidence-backed transaction API", () => {
  assert.match(api, /bankingTransaction/);
  assert.match(api, /\/runtime-control\/banking-transactions/);
  assert.match(types, /export type BankingTransactionProjection/);
  assert.match(page, /api\.bankingTransaction/);
  assert.match(actionTrace, /runtime-intelligence\/transactions/);
});


test("transaction investigation shows coverage, timeline, receipts and blind spots", () => {
  for (const label of [
    "AI Transaction",
    "Control Coverage",
    "Transaction timeline",
    "Decision Receipt",
    "Execution Receipt",
    "Evidence references",
    "Drift & blind spots",
    "Unknown",
    "Not covered",
  ]) {
    assert.ok(page.includes(label), `missing transaction label: ${label}`);
  }
  assert.match(page, /coverage_complete/);
  assert.match(page, /not_applicable/);
  assert.match(page, /response_assurance/);
  assert.doesNotMatch(page, /coverage.*reduce\(/);
  assert.doesNotMatch(page, /customer-001|acct-001/);
});
