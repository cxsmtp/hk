import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../src/app/dashboard/command-center/page.tsx", import.meta.url),
  "utf8",
);

const defaultBranchStart = source.indexOf(
  'if (process.env.NEXT_PUBLIC_LEGACY_COMMAND_CENTER !== "true")',
);
const legacyBranchStart = source.indexOf("\n  return (", defaultBranchStart);
const defaultBranch = source.slice(defaultBranchStart, legacyBranchStart);

test("default Command Center composes the approved visual overview from current data", () => {
  assert.match(source, /deriveGovernanceOverview/);
  assert.match(source, /const governanceOverview = useMemo/);
  assert.match(defaultBranch, /<GovernanceStoryline model=\{governanceOverview\}/);
  assert.match(defaultBranch, /<GovernanceOperations model=\{governanceOverview\} priorityActions=\{priorityActions\}/);
  assert.match(defaultBranch, /<EvidenceRiver events=\{governanceOverview\.river\} live=\{streamConnected\}/);
});

test("the default overview leads with priority activity and keeps narrative detail optional", () => {
  const storyline = defaultBranch.indexOf("<GovernanceStoryline");
  const operations = defaultBranch.indexOf("<GovernanceOperations");
  const river = defaultBranch.indexOf("<EvidenceRiver");
  const priority = defaultBranch.indexOf("<TopActionsNow");
  assert.ok(priority >= 0 && priority < river && river < storyline && storyline < operations);
  assert.match(defaultBranch, /Governance context and coverage/);
});

test("existing detailed controls remain available behind progressive disclosure", () => {
  assert.match(defaultBranch, /<details/);
  assert.match(defaultBranch, /Detailed operating view/);
  for (const required of ["MCPGatewayVisibility", "InteractionSecurityMatrix", "AIIAMPosture", "ControlValidationPanel"]) {
    assert.match(defaultBranch, new RegExp(required));
  }
});

test("existing refresh, filters, runtime stream and platform mode remain connected", () => {
  assert.match(source, /useRuntimeIntelligenceStream/);
  assert.match(source, /setInterval\(\(\) => \{[\s\S]*?load\(false, true\)[\s\S]*?12000/);
  assert.match(defaultBranch, /<PlatformModeControl/);
  assert.match(defaultBranch, /Filter by time window/);
  assert.match(defaultBranch, /Filter by AI system/);
  assert.match(defaultBranch, /Filter by severity/);
});
