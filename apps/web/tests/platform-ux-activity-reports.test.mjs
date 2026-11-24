import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

test("each approval surface retains its complete decision contract", () => {
  const board = source("components/agui-oversight-board.tsx");
  for (const field of ["required_role", "decision_options", "requires_justification", "requires_evidence_display", "requires_diff_preview", "evidence_node_ids", "proof_timeline_url", "decision_payload"]) {
    assert.ok(board.includes(field), `Missing approval contract: ${field}`);
  }
  for (const label of ["Affected record ID", "Supporting evidence IDs", "Evidence has been reviewed prior to decision", "Diff preview", "Current state", "Proposed state", "Technical decision details"]) {
    assert.match(board, new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), `Missing customer-facing approval control: ${label}`);
  }
  for (const forbidden of ["Source Object Summary", "Source Object ID", "Source Object Type", "required contract signal", "decision_payload.current_state", "decision_payload.proposed_state"]) {
    assert.doesNotMatch(board, new RegExp(forbidden.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), `Internal approval label leaked into visible copy: ${forbidden}`);
  }
  const queue = board.indexOf('title="Action Queue"');
  const review = board.indexOf('title="Review selected action"');
  const evidence = board.indexOf('title="Evidence Links"');
  const record = board.indexOf('title="Record decision"');
  const history = board.indexOf('title="Recent Decisions"');
  assert.ok(queue >= 0 && queue < review && review < evidence && evidence < record && record < history, "approval review must proceed from queue to history");
  assert.match(board, /role="alert"/);
  assert.match(board, /Loading approval actions/);
});

test("Activity retains thirteen named views while offering task-first navigation", () => {
  const activity = source("app/ai-tools-usage/page.tsx");
  for (const tab of ["overview", "providers", "users", "prompts", "mcp", "spend", "accounts", "data", "browser", "meeting", "policies", "coverage", "connectors"]) {
    assert.ok(activity.includes(`["${tab}",`), `Missing Activity view: ${tab}`);
  }
  assert.match(activity, /Activity views/);
  assert.match(activity, /aria-label="AI Tools and Usage sections"/);
  assert.ok(activity.indexOf("AI Tools and Usage sections") < activity.indexOf("What this page can prove right now"), "navigation must precede source diagnostics");
  assert.doesNotMatch(activity, /What is live right now|QuickEvidencePanel/);
  assert.equal((activity.match(/aria-label="Activity overview metrics"/g) || []).length, 1, "overview should expose one compact metric strip");
  assert.match(activity, /Source and coverage details/);
  assert.match(activity, /Mixed provider-reported\/billed and estimated sources/);
  assert.match(activity, /Unknown cost source/);
});

test("Reports keeps source failures unavailable and audit job identity technical", () => {
  const evidence = source("components/lifecycle/evidence-workspace.tsx");
  assert.match(evidence, /Promise\.allSettled/);
  assert.match(evidence, /jobsState === "error" \? "Unavailable"/);
  assert.match(evidence, /function humanizeJobName/);
  assert.match(evidence, /Raw job name:/);
  assert.match(evidence, /Source: audit job status API/);
});

test("Reports prioritizes export and preview with explicit unavailable state", () => {
  const reports = source("app/auditor/page.tsx");
  assert.ok(reports.indexOf('title="Audit Actions"') < reports.indexOf("<ModuleReportPanel"), "export action must precede analytics");
  assert.ok(reports.indexOf('title="Proof Feed"') < reports.indexOf("<ModuleReportPanel"), "proof preview must precede analytics");
  assert.match(reports, /Report sources unavailable/);
  assert.match(reports, /No recent proof artifacts/);
});

test("Activity Map leads with activity-chain language while retaining collapsed technical evidence", () => {
  const activityMap = source("app/runtime-intelligence/activity-map/page.tsx");
  const header = activityMap.slice(activityMap.indexOf("<PageHeader"), activityMap.indexOf("<OperationalState"));
  assert.match(header, /title="Activity chain"/);
  assert.match(header, /chain or correlation reference/);
  assert.doesNotMatch(header, /chain_id|correlation_id|React Flow|progressive loading/);

  const loadSectionStart = activityMap.indexOf('<PageSection title="Load an activity chain"');
  const kpiStart = activityMap.indexOf("<KpiStrip", loadSectionStart);
  const loadSection = activityMap.slice(loadSectionStart, kpiStart);
  const technicalDetails = loadSection.indexOf("<details");
  assert.ok(technicalDetails >= 0, "Activity Map technical evidence must be collapsible");
  assert.match(loadSection.slice(0, technicalDetails), /description="Enter a chain or correlation reference/);
  assert.match(loadSection.slice(0, technicalDetails), /placeholder="Enter a chain or correlation reference"/);
  assert.doesNotMatch(loadSection.slice(0, technicalDetails), /chain_id|correlation_id|React Flow|progressive/);
  assert.match(loadSection.slice(technicalDetails), /Technical details/);
  assert.match(loadSection.slice(technicalDetails), /chain_id and correlation_id/);
  assert.match(loadSection.slice(technicalDetails), /React Flow and loads large chains progressively/);
});

test("Recommendations show task cards before the collapsed CRQ explanation", () => {
  const recommendations = source("app/runtime-intelligence/recommendations/page.tsx");
  const cards = recommendations.indexOf('title="Recommendation Cards"');
  const financialDisclosure = recommendations.indexOf("<summary className=\"cursor-pointer text-sm font-semibold text-slate-100\">Financial impact explanation (CRQ)</summary>");
  assert.ok(cards >= 0 && financialDisclosure > cards, "recommendation cards must precede financial material");
  const disclosure = recommendations.slice(financialDisclosure);
  assert.match(disclosure, /Financial Impact Explanation/);
  assert.match(disclosure, /financialSummary\.totalReduction/);
  assert.match(disclosure, /financialSummary\.avgScore/);
  assert.match(disclosure, /financialSummary\.avgConfidence/);
  assert.match(disclosure, /financialSummary\.top\?\.action/);
});
