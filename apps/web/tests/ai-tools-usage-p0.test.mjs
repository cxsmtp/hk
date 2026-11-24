import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(
  new URL("../src/app/ai-tools-usage/page.tsx", import.meta.url),
  "utf8",
);
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("AI Tools & Usage exposes the complete production navigation without demo fallback", () => {
  for (const label of [
    "Overview",
    "Providers",
    "Users & Departments",
    "Prompts & Actions",
    "MCP & Tools",
    "Spend & Utilization",
    "Accounts & Devices",
    "Data, Uploads & Downloads",
    "Browser Extension",
    "Meeting AI",
    "Policies",
    "Coverage & Gaps",
    "Connector Health",
  ]) {
    assert.match(page, new RegExp(label.replace(/[&]/g, "&amp;|&"), "i"));
  }
  assert.doesNotMatch(page, /demoFallback|DEMO DATA/);
  assert.match(page, /Unavailable/);
  assert.match(page, /freshness/i);
  assert.match(page, /source/i);
  assert.match(page, /Provider seat utilization/);
  assert.match(page, /provider-admin aggregate/i);
  assert.match(types, /authoritative_snapshot_count/);
  assert.match(page, /Unassigned seats/);
  assert.match(page, /Unknown activity/);
  assert.match(types, /total_licensed_seats/);
  assert.match(page, /Trusted extension ID/);
  assert.match(page, /Last heartbeat/);
  assert.match(page, /Duplicate extension IDs/);
  assert.match(page, /Removal and tamper evidence/);
  assert.match(page, /managed browser policy or MDM/);
  assert.match(page, /Extension removal governance/);
  assert.match(page, /Admin approval is required for disable\/removal/);
  assert.match(page, /Chrome MDM policy/i);
  assert.match(page, /Safari MDM policy/i);
  assert.match(page, /Admin workflow/);
  assert.match(page, /Audit events/);
  assert.match(page, /Observed client sessions/);
  assert.match(page, /Account classes/);
  assert.match(page, /Device assurance/);
  assert.match(page, /Classified prompt events/);
  assert.match(page, /Upload events/);
  assert.match(page, /Download events/);
  assert.match(page, /Runtime\/client projections/);
  assert.match(page, /Provider-native billing/);
  assert.match(page, /Connect provider-admin source/);
  assert.match(page, /Observed-but-not-canonical/);
  assert.match(types, /accounts_devices/);
  assert.match(types, /classified_prompt_events/);
  assert.match(types, /runtime_projection_count/);
  assert.match(types, /provider_signal_record_count/);
});

test("AI Tools & Usage uses a dedicated tenant API and typed response", () => {
  assert.match(api, /aiToolsUsage:\s*\(\)/);
  assert.match(api, /request<AIToolsUsageWorkspace>\("\/ai-tools-usage\?limit=250"\)/);
  assert.match(api, /browserExtensionHealth:\s*\(\)/);
  assert.match(api, /"\/extension\/health"/);
  assert.match(api, /browserExtensionRemovalGovernance:\s*\(\)/);
  assert.match(api, /"\/extension\/governance\/removal"/);
  assert.match(types, /export type AIToolsUsageWorkspace/);
  assert.match(types, /export type BrowserExtensionHealth/);
  assert.match(types, /export type BrowserExtensionRemovalGovernance/);
  assert.match(page, /api\.aiToolsUsage\(\)/);
  assert.match(page, /api\.browserExtensionHealth\(\)/);
  assert.match(page, /api\.browserExtensionRemovalGovernance\(\)/);
});
