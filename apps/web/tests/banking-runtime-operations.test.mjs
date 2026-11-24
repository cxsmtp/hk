import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";


const commandCenter = readFileSync(
  "src/app/dashboard/command-center/page.tsx",
  "utf8",
);
const cisoSummary = readFileSync(
  "src/components/banking/banking-ciso-summary.tsx",
  "utf8",
);
const transactionPage = readFileSync(
  "src/app/runtime-intelligence/transactions/[id]/page.tsx",
  "utf8",
);
const diagnosticsPage = readFileSync(
  "src/app/runtime-intelligence/transactions/[id]/diagnostics/page.tsx",
  "utf8",
);
const api = readFileSync("src/lib/api.ts", "utf8");
const productionGuide = readFileSync(
  "../../docs/deployment/microsoft-banking-runtime-control.md",
  "utf8",
);


test("existing Command Center exposes the bounded banking CISO summary", () => {
  assert.match(api, /bankingCisoSummary/);
  assert.match(api, /banking-transactions\/summary\/ciso/);
  assert.match(commandCenter, /BankingCisoSummaryPanel/);
  assert.match(commandCenter, /<BankingCisoSummaryPanel\s*\/>/);

  for (const label of [
    "Regulated AI transactions",
    "Customer boundary and execution proof",
    "Inline blockable",
    "Execution verified",
    "Drifted",
    "Current gaps",
    "Unknown",
  ]) {
    assert.ok(cisoSummary.includes(label), `missing CISO label: ${label}`);
  }

  assert.match(cisoSummary, /bounded transaction denominator/);
  assert.match(cisoSummary, /consequential_execution_verified_percent/);
  assert.doesNotMatch(cisoSummary, /customer-001|acct-001|87%|92%/);
});


test("developer diagnostics are separate and linked from the transaction view", () => {
  assert.match(
    transactionPage,
    /runtime-intelligence\/transactions\/\$\{encodeURIComponent\(transactionId\)\}\/diagnostics/,
  );
  assert.match(diagnosticsPage, /api\.bankingTransaction/);
  assert.match(diagnosticsPage, /api\.nativeControlPointHealth/);

  for (const label of [
    "Developer diagnostics",
    "Integration method",
    "Middleware health",
    "Policy version",
    "Action schema",
    "Failed validation",
    "Tool fingerprint",
    "Observed latency",
    "Receipt correlation",
    "Integration contract",
    "Unknown",
  ]) {
    assert.ok(diagnosticsPage.includes(label), `missing developer label: ${label}`);
  }

  assert.match(diagnosticsPage, /tool_fingerprint_reference/);
  assert.match(diagnosticsPage, /control_point_reference/);
  assert.match(diagnosticsPage, /observed_latency_ms/);
  assert.match(diagnosticsPage, /decision_receipt_ids/);
  assert.match(diagnosticsPage, /execution_receipt_ids/);
  assert.match(diagnosticsPage, /coverage_complete/);
  assert.doesNotMatch(diagnosticsPage, /customer-001|acct-001|latency.*12\.5/i);
});


test("production guide covers the required bank integration and operations surfaces", () => {
  for (const heading of [
    "Microsoft Agent Framework integration",
    "Foundry integration",
    "Subject binding",
    "MCP and Toolbox",
    "Identity model",
    "APIM and direct API",
    "Decision Receipt",
    "Execution Receipt",
    "Approval binding",
    "Response assurance",
    "Banking policy reference",
    "Sentinel",
    "Control Coverage",
    "Failure and degradation",
    "Deployment",
    "Data and privacy",
    "Operational runbook",
    "Troubleshooting",
    "Acceptance",
  ]) {
    assert.ok(productionGuide.includes(heading), `missing production guide section: ${heading}`);
  }
  assert.match(productionGuide, /PHASE 1 NOT PRODUCTION-POC READY/);
  assert.match(productionGuide, /EXTERNAL_DEPENDENCY/);
});
